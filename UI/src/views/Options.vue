<script setup lang="ts">
	import { ref, reactive, onMounted, nextTick } from 'vue'
	import { ElMessage, ElMessageBox, ElLoading } from 'element-plus'
	import {
		Unlock,
		Operation,
		VideoCamera,
		InfoFilled,
		Refresh,
		Tools
	} from '@element-plus/icons-vue'
	import { useOptionsStore } from '../stores/options'
	import { invoke } from '@tauri-apps/api/core'
	import { formatObjectString, hashMessage } from '../utils/function'
	import { info, error as errorLog, warn } from '@tauri-apps/plugin-log';
	import { selectCustom } from '../utils/sqlite'
	import { useRouter } from 'vue-router'
	import { openUrl } from '@tauri-apps/plugin-opener';

	const optionsStore = useOptionsStore();
	const router = useRouter();

	const activeTab = ref('app')
	const optionTabs = [
		{ id: 'app', label: '软件配置', icon: Operation },
		{ id: 'dll', label: '系统集成', icon: Unlock },
		{ id: 'maintenance', label: '维护与卸载', icon: Tools },
	]

	const cameraList = ref([]);
	const cameraListLoading = ref(false);
	const autoStartLoading = ref(false);
	const activeNames = ref([]);
	// 解锁服务是否打开了？
	const isServiceRunning = ref(false);
	const config = reactive({
		camera: optionsStore.getOptionValueByKey('camera') || "-1",
		cameraRotation: parseInt(optionsStore.getOptionValueByKey('cameraRotation')) || 0,
		unlockBrightness: parseInt(optionsStore.getOptionValueByKey('unlockBrightness')) || 0,
		autoStart: true,
		faceRecogDelay: parseFloat(optionsStore.getOptionValueByKey('faceRecogDelay')) || 10.0,
		faceRecogType: optionsStore.getOptionValueByKey('faceRecogType') || 'operation',
		silentRun: optionsStore.getOptionValueByKey('silentRun') ? (optionsStore.getOptionValueByKey('silentRun') == 'false' ? false : true) : false,
		retryDelay: parseFloat(optionsStore.getOptionValueByKey('retryDelay')) || 1.0,
		notFaceDelay: parseFloat(optionsStore.getOptionValueByKey('notFaceDelay')) || 3,
		// 是否开机面容识别
		isAutoFaceRecogOnStart: false,
		// 推理后端
		inferenceBackend: optionsStore.getOptionValueByKey('inferenceBackend') || 'cpu',
		// 活体检测的配置
		livenessEnabled: optionsStore.getOptionValueByKey('livenessEnabled') ? (optionsStore.getOptionValueByKey('livenessEnabled') == 'false' ? false : true) : false,
		livenessThreshold: parseFloat(optionsStore.getOptionValueByKey('livenessThreshold')) || 0.50,
		faceAlignedType: optionsStore.getOptionValueByKey('faceAlignedType') || 'default',
		// 登录安全
		loginEnabled: optionsStore.getOptionValueByKey('loginEnabled') ? (optionsStore.getOptionValueByKey('loginEnabled') == 'false' ? false : true) : false,
		loginPassword: optionsStore.getOptionValueByKey('loginPassword') || '',
		loginMethod: optionsStore.getOptionValueByKey('loginMethod') || 'onlyOpenApp',
		// 自动锁屏
		autoLockEnabled: optionsStore.getOptionValueByKey('autoLockEnabled') ? (optionsStore.getOptionValueByKey('autoLockEnabled') == 'false' ? false : true) : false,
		autoLockTimeout: parseInt(optionsStore.getOptionValueByKey('autoLockTimeout')) || 300,
	})

	const dllConfig = reactive({
		showTile: optionsStore.getOptionValueByKey('showTile') ? (optionsStore.getOptionValueByKey('showTile') == 'false' ? false : true) : true,
		unlockScene: (optionsStore.getOptionValueByKey('unlockScene') || '1,2,4').split(',').map((s: string) => s.trim()).filter(Boolean),
		credUiAllowBroker: true,
	})

	const passkeyPlugin = reactive({
		loading: false,
		installed: false,
		sampleInstalled: false,
		version: '',
		bundledVersion: '',
		updateAvailable: false,
		available: false,
	})

	async function refreshPasskeyPluginStatus() {
		passkeyPlugin.loading = true
		try {
			const result: any = await invoke('get_passkey_plugin_status')
			const status = result?.data || {}
			passkeyPlugin.installed = Boolean(status.installed)
			passkeyPlugin.sampleInstalled = Boolean(status.sample_installed)
			passkeyPlugin.version = status.package?.version || status.sample_package?.version || ''
			passkeyPlugin.bundledVersion = status.bundled_version || ''
			passkeyPlugin.updateAvailable = Boolean(status.update_available)
			passkeyPlugin.available = Boolean(status.msix_available && status.certificate_available)
		} catch (error) {
			warn(formatObjectString('查询 Passkey 插件状态失败：', error))
		} finally {
			passkeyPlugin.loading = false
		}
	}

	async function setupPasskeyPlugin() {
		let replaceSample = false
		if (passkeyPlugin.sampleInstalled && !passkeyPlugin.installed) {
			try {
				await ElMessageBox.confirm(
					'替换 Contoso 测试插件会删除其本地保存的通行密钥，网站端旧凭据需要重新注册。确定迁移到正式插件吗？',
					'迁移 Passkey 插件',
					{ type: 'warning', confirmButtonText: '确认迁移', cancelButtonText: '保留测试插件' }
				)
				replaceSample = true
			} catch {
				return
			}
		}

		passkeyPlugin.loading = true
		try {
			const needsInstall = !passkeyPlugin.installed || passkeyPlugin.updateAvailable || replaceSample
			if (needsInstall) {
				if (!passkeyPlugin.available) {
					ElMessage.warning('安装包中缺少 Passkey 插件或签名证书，无法自动安装')
					return
				}
				const result: any = await invoke('install_passkey_plugin', { replaceSample })
				ElMessage.success(result?.msg || 'Passkey 插件已安装')
				await refreshPasskeyPluginStatus()
			}
			await invoke('open_passkey_plugin_setup')
			ElMessage.success('已打开 Passkey 插件注册与启用流程')
		} catch (error) {
			ElMessage.error(formatObjectString('启动 Passkey 插件设置失败：', error))
		} finally {
			passkeyPlugin.loading = false
		}
	}

	async function openPasskeyPluginManager() {
		try {
			await invoke('open_passkey_plugin_manager')
		} catch (error) {
			ElMessage.error(formatObjectString('打开 Passkey 插件管理器失败：', error))
		}
	}

	async function uninstallPasskeyPlugin() {
		// 二选项：保留通行密钥卸载（默认，重装/全量更新可复用）vs 彻底清除（不可恢复）。
		// confirm 按钮=保留；cancel 按钮=彻底清除；关闭(X/ESC)=取消操作。
		let purge = false
		try {
			await ElMessageBox.confirm(
				'选择卸载方式：<br/><br/>' +
				'<b>保留通行密钥</b>（推荐）：卸载插件但保留本地通行密钥与私钥，重装/全量更新后可继续使用，无需重新注册。<br/><br/>' +
				'<b>彻底清除</b>：删除插件及所有本地通行密钥、私钥、证书，网站端凭据将失效、需重新注册，不可恢复。',
				'卸载 Passkey 插件',
				{
					type: 'warning',
					dangerouslyUseHTMLString: true,
					confirmButtonText: '保留密钥卸载',
					cancelButtonText: '彻底清除',
					distinguishCancelAndClose: true,
					showClose: true,
				}
			)
			purge = false
		} catch (action) {
			if (action === 'cancel') {
				purge = true
			} else {
				return
			}
		}

		if (purge) {
			try {
				await ElMessageBox.confirm(
					'确定彻底清除？所有本地通行密钥与私钥将永久删除，无法恢复。',
					'彻底清除确认',
					{ type: 'error', confirmButtonText: '确认彻底清除', cancelButtonText: '取消' }
				)
			} catch {
				return
			}
		}

		passkeyPlugin.loading = true
		try {
			const result: any = await invoke('uninstall_passkey_plugin', { purge })
			ElMessage.success(result?.msg || 'Passkey 插件已卸载')
			await refreshPasskeyPluginStatus()
		} catch (error) {
			ElMessage.error(formatObjectString('卸载 Passkey 插件失败：', error))
		} finally {
			passkeyPlugin.loading = false
		}
	}

	// 清理插件残留的 KSP 私钥：插件「清空/删除通行密钥」只删元数据与 Windows 索引、不删私钥（issue #3）。
	async function cleanupResidualKeys() {
		try {
			await ElMessageBox.confirm(
				'将删除本机残留的 FaceWinUnlock 通行密钥私钥——插件的「清空/删除」不会删除这些私钥。<br/><br/>' +
				'若你仍在使用之前注册的通行密钥，请勿清理；清理后相关站点需重新注册。确定清理吗？',
				'清理残留私钥',
				{ type: 'warning', dangerouslyUseHTMLString: true, confirmButtonText: '确认清理', cancelButtonText: '取消' }
			)
		} catch {
			return
		}
		passkeyPlugin.loading = true
		try {
			const result: any = await invoke('cleanup_passkey_residual_keys')
			ElMessage.success(result?.msg || '已清理残留私钥')
		} catch (error) {
			ElMessage.error(formatObjectString('清理残留私钥失败：', error))
		} finally {
			passkeyPlugin.loading = false
		}
	}

	// 首次打开「软件配置」时，避免在 setup 同步阶段同时 spawn 多个外部进程
	//（schtasks ×2 + 命名管道 + PowerShell Get-AppxPackage）与首屏渲染竞争造成明显卡顿：
	// 统一移到 onMounted + nextTick，让首屏先绘制完成，再分批加载各项状态；
	// Passkey 状态走 PowerShell（首次启动进程 1-3s 最慢），额外延迟错开，进一步避开首屏。
	onMounted(() => {
		nextTick(() => {
			invoke("check_scheduled_task", { taskName: 'FaceWinUnlockAutoStart' }).then((result: any) => {
				config.autoStart = result.data.enable;
			}).catch((error) => {
				ElMessage.warning(formatObjectString("查询自启状态失败 ", error));
			});
			checkServiceRunning(null);
			checkAutoFaceRecogOnStart(null);
			setTimeout(() => { refreshPasskeyPluginStatus(); }, 200);
		});
	});

	const refreshCameraList = ()=>{
		cameraListLoading.value = true;
		// 因为不确定之前摄像头是否还可用，强制设为-1
		config.camera = "-1";
		// 获取摄像头列表
		invoke("get_camera").then((result)=>{
			// 清空列表
			cameraList.value.length = 0;

			// 添加列表
			result.data.forEach(item => {
				if(config.camera == "-1"){
					config.camera = item.capture_index;
				}
				cameraList.value.push(item);
			});

			// 立即添加到数据库，不能等用户点
			return optionsStore.saveOptions({
				cameraList: JSON.stringify(cameraList.value),
				camera: config.camera
			});
		}).then(()=>{
			ElMessage.success("获取摄像头列表成功");
		}).catch((error)=>{
			ElMessage.error(formatObjectString(error));
		}).finally(()=>{
			cameraListLoading.value = false;
		})
	}

	// 判断是否获取过摄像头列表
	let tempCameraList = optionsStore.getOptionValueByKey('cameraList');
	if(!tempCameraList){
		refreshCameraList();
	}else{
		cameraList.value = JSON.parse(tempCameraList);
	}

	// 自启切换
	const handleAutoStartChange = ()=>{
		autoStartLoading.value = true;
		if(config.autoStart){
			invoke("add_scheduled_task", {
				path: 'facewinunlock-tauri.exe', taskName: 'FaceWinUnlockAutoStart', isServer: false, silent: true, runOnSystemStart: false, runImmediately: false
			}).catch((e)=>{
				config.autoStart = false;
				ElMessage.error(formatObjectString(e));
			}).finally(()=>{
				autoStartLoading.value = false;
			});
		}else{
			invoke("disable_scheduled_task", {taskName: 'FaceWinUnlockAutoStart'}).catch(()=>{
				config.autoStart = true;
				ElMessage.error("取消开机启动失败，请重新尝试");
			}).finally(()=>{
				autoStartLoading.value = false;
			});
		}
	}

	// 推理后端名称到 OpenCV DNN backend/target ID 的映射
	const INFERENCE_BACKEND_MAP: Record<string, { backend: number; target: number }> = {
		'cpu':         { backend: 0, target: 0 },
		'opencl':      { backend: 3, target: 1 },
		'opencl_fp16': { backend: 3, target: 2 },
		'intel_npu':   { backend: 2, target: 9 },
	};

	// 用户在下拉框中切换推理后端时，对非 CPU 后端做一次可用性探测：
	// 尝试用该后端加载模型，若服务自动回退到 CPU，则立即提示用户
	// （直接回答 issue #125 用户"是我缺少什么文件么"的疑问）。
	const onInferenceBackendChange = async (value: string) => {
		if (value === 'cpu') return;
		const { backend, target } = INFERENCE_BACKEND_MAP[value] ?? { backend: 0, target: 0 };
		const loadingInstance = ElLoading.service({ fullscreen: true, text: '正在检测所选推理后端是否可用…' });
		try {
			// 先卸载，确保此次探测真正用所选后端重新加载
			await invoke('unload_model').catch(() => {});
			const result: any = await invoke('load_opencv_model', { backend, target });
			if (result && result.fell_back) {
				warn(`推理后端 ${value} 不可用，已回退 CPU：${result.fallback_reason || ''}`);
				ElMessage.warning({
					dangerouslyUseHTMLString: true,
					message: `所选推理后端 <b>${value}</b> 不可用，识别时会自动回退到 CPU。<br />` +
						(value === 'intel_npu'
							? 'Intel NPU 需额外安装 <b>OpenVINO 运行时</b> 及对应的 OpenCV DNN 插件 DLL。'
							: '请确认显卡及驱动支持 OpenCL。')
				});
			} else if (value === 'opencl' || value === 'opencl_fp16') {
				// OpenCL/FP16 加载会"成功"，但首次推理要编译 OpenCL kernel + auto-tuning（会卡一下，
				// 已由 OPENCV_OCL4DNN_CONFIG_PATH 缓存使首次之后秒级）；且个别显卡 FP16 精度不足会导致
				// 「匹配不上」（加载阶段无法预知，缓存也救不了）（issue #3）。给出实验性警告，引导遇异常改回 CPU。
				ElMessageBox.alert(
					'GPU（OpenCL）后端为实验性：首次使用需预热编译 OpenCL kernel，会卡顿一下（之后已缓存、恢复流畅）；' +
					'且个别显卡 FP16 精度不足时可能出现人脸「匹配不上」（锁屏一直转圈不自动解锁）。' +
					'若遇到解锁失败或识别异常，请把推理后端改回 CPU（CPU 兼容性最好）。',
					'GPU 后端为实验性',
					{ type: 'warning', confirmButtonText: '我知道了' }
				).catch(() => {});
			} else {
				ElMessage.success(`推理后端 ${value} 可用`);
			}
		} catch (error) {
			ElMessage.error(formatObjectString('检测推理后端失败：', error));
		} finally {
			// 探测完毕卸载模型，避免长期占用
			await invoke('unload_model').catch(() => {});
			loadingInstance.close();
		}
	};

	const saveAppConfig = async () => {
		// 登录安全，如果启用了登录，那么密码不能为空
		if(config.loginEnabled && !config.loginPassword.trim()){
			ElMessage.warning("登录密码不能为空");
			return;
		}

		// 判断是否更改了，如果更改了，需要重新加密
		if(config.loginPassword.trim() != optionsStore.getOptionValueByKey('loginPassword')){
			// 重新加密密码
			const hashedPassword = await hashMessage(config.loginPassword.trim());
			config.loginPassword = hashedPassword;
		}

		const loadingInstance = ElLoading.service({ fullscreen: true });

		optionsStore.saveOptions({
			camera: config.camera,
			cameraRotation: String(config.cameraRotation),
			unlockBrightness: String(config.unlockBrightness),
			faceRecogDelay: config.faceRecogDelay,
			faceRecogType: config.faceRecogType,
			silentRun: config.silentRun,
			retryDelay: config.retryDelay,
			notFaceDelay: isNaN(parseInt(config.notFaceDelay)) ? "3" : String(parseInt(config.notFaceDelay)),
			inferenceBackend: config.inferenceBackend,
			livenessEnabled: config.livenessEnabled,
			livenessThreshold: config.livenessThreshold,
			faceAlignedType: config.faceAlignedType,
			loginEnabled: config.loginEnabled ? "true" : "false",
			loginPassword: config.loginPassword,
			loginMethod: config.loginMethod,
			autoLockEnabled: config.autoLockEnabled ? "true" : "false",
			autoLockTimeout: String(config.autoLockTimeout),
		}).then((errorArray)=>{
			if(errorArray.length > 0){
				ElMessage.warning({
                    dangerouslyUseHTMLString: true,
                    message: `${errorArray.length} 个配置保存失败: <br />${errorArray.join("<br />")}`
                })
			}else{
				ElMessage.success("保存成功");
			}
			return invoke("write_to_registry", {items: [
				{
					key: "RETRY_DELAY",
					value: String(Math.max(1, Number(config.retryDelay) || 1.0))
				}
			]}).catch((error)=>{
				warn(formatObjectString("同步 RETRY_DELAY 至注册表失败：", error));
			})
		}).catch().finally(()=>{
			loadingInstance.close();
		});
	}
	const applyDllSettings = () => {
		const loadingInstance = ElLoading.service({ fullscreen: true });

		invoke("write_to_registry", {items: [
			{
				key: "SHOW_TILE",
				value: dllConfig.showTile ? "1" : "0"
			},
			{
				key: "UNLOCK_SCENE",
				value: dllConfig.unlockScene.join(',')
			},
			{
				key: "CREDUI_ALLOW_BROKER",
				value: "1"
			},
			{
				key: "CREDUI_BROKER_FALLBACK_TIMEOUT",
				value: "5.0"
			}
		]}).then(()=>{
			return optionsStore.saveOptions({
				showTile: dllConfig.showTile,
				unlockScene: dllConfig.unlockScene.join(','),
				credUiAllowBroker: "true"
			})
		}).then((errorArray)=>{
			if(errorArray.length > 0){
				ElMessage.warning({
                    dangerouslyUseHTMLString: true,
                    message: `${errorArray.length} 个配置保存失败: <br />${errorArray.join("<br />")}`
                })
			}else{
				ElMessage.success("保存成功");
			}
		}).catch((error)=>{
			const info = formatObjectString("保存DLL配置失败: ", error);
			ElMessage.error(info);
			errorLog(info);
		}).finally(()=>{
			loadingInstance.close();
		});
	}

	const clearCache = () => {
		ElMessageBox.confirm('这将清除数据库缓存，软件缓存请手动关闭软件后，删除打开的 EBWebView 文件夹', '注意', {
			confirmButtonText: '确定清除',
			cancelButtonText: '取消',
			type: 'warning'
		}).then(async () => {
			try {
				await selectCustom("VACUUM;");
			} catch (error) {
				const info = formatObjectString("删除数据库缓存失败: ", error);
				ElMessage.error(info);
				errorLog(info);
				return;
			}

			// 走到这，其实 EBWebView 必然是被软件占用的，所以直接rust删除必定会失败
			// 但也有一些方法，但是我懒得写了，后面看到的大佬，有想实现的，可以自己实现一下
			// 	1. 用win32 Api单独写一个程序，点到这里唤醒程序，等本程序退出后，清除缓存
			// 	2. 用win32包裹此程序启动，启动时先启动win32的程序，判断缓存目录是否有清除标记，如果有就清除缓存，并启动本软件，如果没有直接启动本软件
			// 	   当走到这里时，给缓存目录添加标记，等待下一次开启自动清除
			ElMessageBox.alert('数据库缓存已清除，即将打开软件缓存目录，请在关闭软件后，删除 EBWebView 文件夹', '提示', {
				confirmButtonText: '确定',
				callback: () => {
					invoke("get_cache_dir").then((result)=>{
						return invoke("open_directory", {path: result})
					}).catch((error)=>{
						const info = formatObjectString("打开文件夹失败: ", error);
						ElMessage.error(info);
						errorLog(info);
					})
				},
			})
		})
	}

	const uninstallDll = () => {
		ElMessageBox.confirm(
			'卸载 DLL、核心服务和 Passkey 插件，并还原注册表。插件本地通行密钥会被删除，网站端使用该插件注册的凭据需要重新注册。程序将强制回到初始化页面。',
			'危险操作',
			{
				confirmButtonText: '确定卸载',
				confirmButtonClass: 'el-button--danger',
				cancelButtonText: '取消',
				type: 'error'
			}
		).then(() => {
			invoke("uninstall_init").then(()=>{
				return optionsStore.saveOptions({is_initialized: 'false'});
			}).then((errorList)=>{
				if (errorList.length > 0) {
					ElMessageBox.alert(formatObjectString(errorList), '保存设置失败', {
						confirmButtonText: '确定'
					});
				} else {
					ElMessage.success('组件已卸载，并撤回了软件对注册表的操作！');
					router.push('/init');
				}
			}).catch((error)=>{
				const info = formatObjectString("卸载组件失败：", error);
				ElMessage.error(info);
				errorLog(info);
			})
		})
	}

	const toggleService = ()=>{
		const loadingInstance = ElLoading.service({ fullscreen: true });
		if(isServiceRunning.value){
			ElMessageBox.confirm(
				'关闭核心服务后，将无法使用面容解锁。', 
				'警告', 
				{
					confirmButtonText: '确定关闭',
					confirmButtonClass: 'el-button--danger',
					cancelButtonText: '取消',
					type: 'warning'
				}
			).then(() => {
				invoke("delete_process_running").then(()=>{
					// 等待关闭管道
					setTimeout(()=>{
						checkServiceRunning(loadingInstance, "核心服务已关闭");
					}, 1000);
				}).catch((error)=>{
					const info = formatObjectString("关闭服务失败：", error);
					ElMessage.error(info);
					errorLog(info);
				})
			}).catch(()=>{
				loadingInstance.close();
			})
		}else{
			invoke("run_scheduled_task", {taskName: "FaceWinUnlockServer"}).then(()=>{
				// 等待运行管道
				setTimeout(()=>{
					checkServiceRunning(loadingInstance, "核心服务已开启");
				}, 1000);
			}).catch((error)=>{
				const info = formatObjectString("开启服务失败：", error);
				ElMessage.error(info);
				errorLog(info);
				loadingInstance.close();
			});
		}
	}

	// 开机面容识别切换
	const handleAutoFaceRecogOnStartChange = ()=>{
		const expectedAutoFaceRecogOnStart = config.isAutoFaceRecogOnStart;
		// 不管切换成什么，都要删除计划任务重新创建
		const loadingInstance = ElLoading.service({ fullscreen: true });
		invoke("disable_scheduled_task", {taskName: 'FaceWinUnlockServer'}).catch(()=>null).then(()=>{
			if(expectedAutoFaceRecogOnStart){
				return invoke("add_scheduled_task", {
					path: 'FaceWinUnlock-Server.exe', taskName: 'FaceWinUnlockServer', isServer: true, silent: false, runOnSystemStart: true, runImmediately: true
				})
			}else{
				return invoke("add_scheduled_task", {
					path: 'FaceWinUnlock-Server.exe', taskName: 'FaceWinUnlockServer', isServer: true, silent: false, runOnSystemStart: false, runImmediately: false
				})
			}
		}).then(()=>{
			config.isAutoFaceRecogOnStart = expectedAutoFaceRecogOnStart;
			checkAutoFaceRecogOnStart(loadingInstance, "开机面容识别已" + (expectedAutoFaceRecogOnStart ? "开启" : "关闭"), expectedAutoFaceRecogOnStart);
		}).catch(()=>{
			config.isAutoFaceRecogOnStart = false;
			ElMessage.error("取消开机面容识别失败，请重新尝试");
			loadingInstance.close();
		});
		
	}

	// 活体检测开关切换
	const livenessEnabledChange = ()=>{
		if(config.livenessEnabled){
			ElMessageBox.confirm(
				'活体检测准确率低，<span style="color: var(--v7-cinnabar-bright);">误判极高，不建议开启</span><br />' +
				'当前只影响录入页面的一致性验证，不参与锁屏解锁<br />' +
				'是否继续开启活体检测？', 
				'警告', 
				{
					dangerouslyUseHTMLString: true,
					confirmButtonText: '我明白风险，继续开启',
					confirmButtonClass: 'el-button--danger',
					cancelButtonText: '取消',
					type: 'warning'
				}
			).then(() => {
				// 继续开启活体检测
			}).catch(() => {
				// 取消开启活体检测
				config.livenessEnabled = false;
			});
		}else{
			// 关闭活体检测
		}
	}

	function checkServiceRunning(loadingInstance, msg = ""){
		invoke("check_process_running").then(()=>{
			if(msg != ""){
				ElMessage.success(msg);
			}
			isServiceRunning.value = true;
		}).catch(()=>{
			if(msg != ""){
				ElMessage.success(msg);
			}
			isServiceRunning.value = false;
		}).finally(()=>{
			if(loadingInstance){
				loadingInstance.close();
			}
		})
	}

	// 检查开机面容识别
	function checkAutoFaceRecogOnStart(loadingInstance, msg = "", expectedState = null){
		invoke("check_trigger_via_xml", {taskName: 'FaceWinUnlockServer'}).then((result)=>{
			if(result == "OnStart"){
				config.isAutoFaceRecogOnStart = true;
				if(msg != ""){
					ElMessage.success(msg);
				}
			}else if(result == "OnLogon"){
				config.isAutoFaceRecogOnStart = false;
				if(msg != ""){
					ElMessage.success(msg);
				}
			} else {
				if(expectedState !== null){
					config.isAutoFaceRecogOnStart = expectedState;
					if(msg != ""){
						ElMessage.success(msg);
					}
				}else{
					ElMessage.warning("未检测到开机面容识别任务触发器，可能未设置或已损坏");
					config.isAutoFaceRecogOnStart = false;
				}
			}
		}).catch((error)=>{
			ElMessage.warning(formatObjectString("查询开机面容识别状态失败 ", error));
		}).finally(()=>{
			if(loadingInstance){
				loadingInstance.close();
			}
		})
	}
</script>

<template>
	<div class="options-container">
		<div class="settings-card">
			<div class="settings-header">
				<div class="glass-radio-group" role="radiogroup" aria-label="配置分类">
					<template v-for="tab in optionTabs" :key="tab.id">
						<input
							v-model="activeTab"
							type="radio"
							name="option-tab"
							:id="`option-tab-${tab.id}`"
							:value="tab.id"
						/>
						<label :for="`option-tab-${tab.id}`">
							<el-icon>
								<component :is="tab.icon" />
							</el-icon>
							<span>{{ tab.label }}</span>
						</label>
					</template>
					<div class="glass-glider" :class="`is-${activeTab}`"></div>
				</div>
				<div class="header-actions">
					<el-button type="primary" size="large" icon="Cpu"
						@click="activeTab === 'dll' ? applyDllSettings() : saveAppConfig()">
						{{ activeTab === 'dll' ? '同步至系统注册表' : '保存本地配置' }}
					</el-button>
					<el-button type="info" plain @click="openUrl('https://github.com/starnotes-xj/FaceWinUnlock-Tauri')">GitHub</el-button>
				</div>
			</div>

			<div class="options-content">
				<div v-if="activeTab === 'app'" class="fade-in">
					<el-collapse v-model="activeNames" :expand-icon-position="'left'">
  						<el-collapse-item title="识别参数" name="1">
							<el-form label-position="top">
								<el-form-item label="默认采集设备">
									<div class="select-with-refresh">
										<el-select v-model="config.camera" style="width: 100%">
											<template #prefix>
												<el-icon>
													<VideoCamera />
												</el-icon>
											</template>
											<el-option v-for="item in cameraList" :key="item.capture_index" :value="item.capture_index" :label="item.camera_name" :disabled="!item.is_valid"/>
										</el-select>
										<el-button
											:icon="Refresh"
											class="refresh-camera-btn"
											title="刷新采集设备列表"
											:loading="cameraListLoading"
											@click="refreshCameraList"
										/>
									</div>
								</el-form-item>
								<el-form-item label="摄像头旋转">
									<el-select v-model="config.cameraRotation" style="width: 100%">
										<el-option :value="0" label="不旋转（默认）"/>
										<el-option :value="90" label="顺时针 90°"/>
										<el-option :value="180" label="旋转 180°"/>
										<el-option :value="270" label="逆时针 90°"/>
									</el-select>
									<p class="row-help">
										适用于笔记本侧放等摄像头朝向不正的场景，保存后录入人脸时实时生效。
									</p>
								</el-form-item>
								<el-form-item label="解锁时屏幕亮度">
									<el-input-number
										v-model="config.unlockBrightness"
										:min="0"
										:max="100"
										:step="10"
										style="width: 140px;"
									/>
									<p class="row-help">
										面容识别期间临时提升屏幕亮度，完成后自动恢复。0 = 不调节；建议 80~100 以改善弱光下解锁成功率。仅支持笔记本内置屏（外接显示器无效）。
									</p>
								</el-form-item>
								<el-form-item label="推理后端">
									<el-select v-model="config.inferenceBackend" style="width: 100%" @change="onInferenceBackendChange">
										<el-option value="cpu" label="CPU（默认，兼容所有设备）"/>
										<el-option value="opencl" label="GPU - OpenCL（需要支持 OpenCL 的显卡）"/>
										<el-option value="opencl_fp16" label="GPU - OpenCL FP16（更快，支持 FP16 的显卡）"/>
										<el-option value="intel_npu" label="Intel NPU（需要安装 OpenVINO 运行时）"/>
									</el-select>
									<p class="row-help">
										保存后录入和锁屏解锁都会使用该后端；服务会在下次识别前重载模型，OpenCL/NPU 加载失败时自动回退 CPU 并写入服务日志。
									</p>
								</el-form-item>
							</el-form>
						</el-collapse-item>
					

						<el-collapse-item title="通用行为" name="2">
							<div class="option-row">
								<div class="row-text">
									<p class="label">随 Windows 自动启动 *</p>
									<p class="sub">登录系统后自动启动面容管理程序（不影响面容识别，不用点保存）</p>
								</div>
								<el-switch v-model="config.autoStart" @change="handleAutoStartChange" :disabled="autoStartLoading"/>
							</div>
							<div class="option-row">
								<div class="row-text">
									<p class="label">开机面容识别 *</p>
									<p class="sub">第一次开机时就可以使用面容识别（不用点保存）</p>
								</div>
								<el-switch v-model="config.isAutoFaceRecogOnStart" @change="handleAutoFaceRecogOnStartChange" />
							</div>
							<div class="option-row">
								<div class="row-text">
									<p class="label">是否静默自启</p>
									<p class="sub">软件开机自动后，隐藏窗口界面</p>
								</div>
								<el-switch v-model="config.silentRun"/>
							</div>
							<div class="option-row">
								<div class="row-text">
									<p class="label">面容识别方式</p>
									<p class="sub">锁屏完成后，用什么方式调用面容识别代码</p>
								</div>
								<el-select v-model="config.faceRecogType" style="width: 170px">
									<el-option :value="'operation'" :label="'用户操作 (支持重试)'"/>
									<el-option :value="'delay'" :label="'延迟时间'"/>
								</el-select>
							</div>
							<div class="option-row" v-if="config.faceRecogType === 'delay'">
								<div class="row-text">
									<p class="label">锁屏后面容识别延迟（秒）</p>
									<p class="sub">锁屏完成后，延迟指定秒数调用摄像头进行面容识别</p>
								</div>
								<el-input-number 
									v-model="config.faceRecogDelay"
									:min="0.1" 
									:max="120" 
									:step="1" 
									:precision="1"
									style="width: 120px;"
								/>
							</div>
							<div class="option-row" v-else>
								<div class="row-text">
									<p class="label">重试时间（秒）</p>
									<p class="sub">在面容不匹配时，时隔多长时间允许重试</p>
								</div>
								<el-input-number 
									v-model="config.retryDelay"
									:min="1" 
									:max="120" 
									:step="1" 
									:precision="1"
									style="width: 120px;"
								/>
							</div>
							<div class="option-row">
								<div class="row-text">
									<p class="label">未检测到面容延迟（秒）</p>
									<p class="sub">未检测到面容时，时隔多长时间停止运行面容识别解锁</p>
								</div>
								<el-input-number 
									v-model="config.notFaceDelay"
									:min="1" 
									:max="120" 
									:step="1" 
									style="width: 120px;"
								/>
							</div>
						</el-collapse-item>
					
						<el-collapse-item title="录入一致性验证" name="3">
							<!-- 活体检测开关 -->
							<div class="option-row">
								<div class="row-text">
									<p class="label">一致性验证启用活体检测</p>
									<p class="sub">仅用于录入页面的人脸一致性验证，不参与锁屏解锁；准确率不高，不推荐开启</p>
								</div>
								<el-switch v-model="config.livenessEnabled" @change="livenessEnabledChange"/>
							</div>

							<!-- 阈值设置 -->
							<div class="option-row">
								<div class="row-text">
									<p class="label">假体置信度阈值</p>
									<p class="sub">阈值越高，安全性越好，假脸被当作真人的概率越低，建议 0.3~0.7</p>
								</div>
								<el-input-number
									v-model="config.livenessThreshold"
									:min="0.1"
									:max="0.99"
									:step="0.01"
									:precision="2"
									style="width: 120px;"
								/>
							</div>

							<!-- 面容对齐方式 -->
							<div class="option-row">
								<div class="row-text">
									<p class="label">面容对齐方式</p>
									<p class="sub">录入一致性验证时识别到面容后以何种方式对齐人脸</p>
								</div>
								<el-select v-model="config.faceAlignedType" style="width: 170px">
									<el-option :value="'default'" :label="'默认对齐'"/>
									<el-option :value="'model'" :label="'模型对齐'"/>
								</el-select>
							</div>
						</el-collapse-item>

						<el-collapse-item title="登录安全" name="4">
							<div class="option-row">
								<div class="row-text">
									<p class="label">启用应用登录</p>
									<p class="sub">打开应用时需要输入密码验证，增强安全性</p>
								</div>
								<el-switch v-model="config.loginEnabled" />
							</div>
							<template v-if="config.loginEnabled">
								<div class="option-row">
									<div class="row-text">
										<p class="label">登录密码</p>
										<p class="sub">设置程序的登录密码，
											<span
												:class="config.loginPassword === optionsStore.getOptionValueByKey('loginPassword') ? 'status-danger' : 'status-success'"
											>
												{{ config.loginPassword === optionsStore.getOptionValueByKey('loginPassword') ? '当前为密文' : '点击保存后加密' }}
											</span>
										</p>
									</div>
									<el-input v-model="config.loginPassword" type="password" show-password  style="width: 170px"/>
								</div>
								<div class="option-row">
									<div class="row-text">
										<p class="label">登录过期时间</p>
										<p class="sub">登录状态过期后需要重新输入密码</p>
									</div>
									<el-select v-model="config.loginMethod" style="width: 170px">
										<el-option :value="'onlyOpenApp'" :label="'第1次打开软件时'"/>
										<el-option :value="'showApp'" :label="'每次打开软件时'"/>
										<el-option :value="'time:1'" :label="'1分钟过期'"/>
										<el-option :value="'time:5'" :label="'5分钟过期'"/>
										<el-option :value="'time:10'" :label="'10分钟过期'"/>
										<el-option :value="'time:15'" :label="'15分钟过期'"/>
										<el-option :value="'time:30'" :label="'30分钟过期'"/>
										<el-option :value="'time:60'" :label="'1小时过期'"/>
									</el-select>
								</div>
							</template>
						</el-collapse-item>
						<el-collapse-item title="自动锁屏" name="5">
							<div class="option-row">
								<div class="row-text">
									<p class="label">启用自动锁屏</p>
									<p class="sub">鼠标键盘闲置超时后，通过摄像头核验当前使用者，若不是授权人员则自动锁屏</p>
								</div>
								<el-switch v-model="config.autoLockEnabled" />
							</div>
							<div class="option-row" style="margin-top: 12px;">
								<div class="row-text">
									<p class="label">闲置超时</p>
									<p class="sub">鼠标键盘无操作的秒数（默认 300 = 5分钟）</p>
								</div>
								<el-input-number v-model="config.autoLockTimeout" :min="30" :max="3600" :step="30" style="width: 140px"/>
							</div>
						</el-collapse-item>
					</el-collapse>
					
				</div>

				<div v-if="activeTab === 'dll'" class="fade-in">
					<div class="option-desc">
						<el-alert title="系统级配置修改" type="info" description="以上选项通过 Rust 后端同步至 Windows 注册表，修改后需要重新锁定计算机生效。"
							show-icon :closable="false" />
					</div>

					<div class="dll-settings">
						<div class="option-row">
							<div class="row-text">
								<p class="label">启用登录界面磁贴 (Tile)</p>
								<p class="sub">在 Windows 锁屏界面显示解锁磁贴</p>
							</div>
							<el-switch v-model="dllConfig.showTile" />
						</div>
						<div class="setting-block">
							<div class="row-text" style="margin-bottom: 12px;">
								<p class="label">面容识别场景</p>
								<p class="sub">
									选择哪些场景下启用面容解锁。<br />
									UAC / 应用层：保留 UAC 提权与浏览器密码查看；通行密钥登录由官方插件处理。
								</p>
							</div>
							<el-checkbox-group v-model="dllConfig.unlockScene" style="display: flex; flex-direction: column; gap: 8px;">
								<el-checkbox label="1">登录（开机登录界面）</el-checkbox>
								<el-checkbox label="2">解锁（锁屏解锁界面）</el-checkbox>
								<el-checkbox label="4">UAC / 应用层（含 Chrome / Edge 查看密码）</el-checkbox>
							</el-checkbox-group>
						</div>
						<div class="option-row">
							<div class="row-text">
								<p class="label">浏览器 broker 弹窗</p>
								<p class="sub">Chrome / Edge 查看密码等 CredUI 场景先使用人脸；通行密钥认证由下方官方插件独立处理。</p>
							</div>
							<el-tag type="success">人脸优先</el-tag>
						</div>
						<div class="setting-block">
							<div class="row-text">
								<p class="label">FaceWinUnlock Passkey Provider</p>
								<p class="sub">
									官方 Windows 插件路线：插件持有自己的不可导出密钥，人脸识别只完成用户验证。<br />
									不提取 Windows Hello 私钥，不保存 PIN，也不需要浏览器扩展；仅在你需要 FaceWinUnlock 自有通行密钥时手动安装和启用。
								</p>
							</div>
							<div class="plugin-actions">
								<el-tag v-if="passkeyPlugin.installed" type="success">
									正式插件已安装{{ passkeyPlugin.version ? `（${passkeyPlugin.version}）` : '' }}
								</el-tag>
								<el-tag v-if="passkeyPlugin.installed && passkeyPlugin.updateAvailable" type="warning">
									可更新到 {{ passkeyPlugin.bundledVersion }}
								</el-tag>
								<el-tag v-else-if="passkeyPlugin.sampleInstalled" type="warning">
									Contoso 测试插件已安装
								</el-tag>
								<el-tag v-else type="info">未安装</el-tag>
								<el-button
									type="primary"
									size="small"
									:loading="passkeyPlugin.loading"
									:disabled="(!passkeyPlugin.installed || passkeyPlugin.updateAvailable) && !passkeyPlugin.available"
									@click="setupPasskeyPlugin"
								>{{ passkeyPlugin.installed ? (passkeyPlugin.updateAvailable ? '更新并打开启用页' : '打开注册/启用流程') : '安装并打开启用页' }}</el-button>
								<el-button
									v-if="passkeyPlugin.installed || passkeyPlugin.sampleInstalled"
									size="small"
									@click="openPasskeyPluginManager"
								>打开管理器</el-button>
								<el-button size="small" :loading="passkeyPlugin.loading" @click="refreshPasskeyPluginStatus">刷新</el-button>
								<el-button
									v-if="passkeyPlugin.installed || passkeyPlugin.sampleInstalled"
									size="small"
									type="danger"
									:loading="passkeyPlugin.loading"
									@click="uninstallPasskeyPlugin"
								>卸载插件</el-button>
								<el-button
									size="small"
									type="warning"
									plain
									:loading="passkeyPlugin.loading"
									@click="cleanupResidualKeys"
								>清理残留私钥</el-button>
							</div>
							<p v-if="passkeyPlugin.sampleInstalled && !passkeyPlugin.installed" class="sub" style="margin-top:10px;">
								迁移会删除测试插件本地凭据，网站端需使用正式插件重新注册通行密钥。
							</p>
							<p class="sub muted">
								Passkey 插件启用后可能被 Windows 作为可用通行密钥 Provider 调用。若要继续优先使用 Windows Hello 原生通行密钥，可不安装此插件，或在 Windows 通行密钥高级设置中停用/在此处保留密钥卸载。
							</p>
						</div>

					</div>
				</div>

				<div v-if="activeTab === 'maintenance'" class="fade-in">
					<section class="config-group danger-zone">
						<h4 class="group-title red-text">维护与卸载</h4>
						<div class="danger-box">
							<div class="danger-item">
								<span>清除数据库和软件缓存</span>
								<el-button type="warning" size="small" plain @click="clearCache">点击清除</el-button>
							</div>
							<el-divider />
							<div class="danger-item">
								<span>{{ isServiceRunning ? '关闭' : '开启' }}解锁服务</span>
								<el-button type="warning" size="small" plain @click="toggleService">{{ isServiceRunning ? '点击关闭' : '点击开启' }}</el-button>
							</div>
							<el-divider />
							<div class="danger-item">
								<span>重新初始化</span>
								<el-button type="warning" size="small" plain @click="$router.push('/init')">点击初始化</el-button>
							</div>
							<p class="danger-footer">
								<el-icon>
									<InfoFilled />
								</el-icon> 初始化需要管理员权限
							</p>
							<el-divider />
							<div class="danger-item">
								<span>卸载核心组件和服务</span>
								<el-button type="danger" size="small" @click="uninstallDll">点击卸载</el-button>
							</div>
							<p class="danger-footer">
								<el-icon>
									<InfoFilled />
								</el-icon> 卸载操作需要管理员权限
							</p>
						</div>
					</section>
				</div>
			</div>
		</div>
	</div>
</template>

<style scoped>
	.options-container {
		height: 100%;
		color: var(--v7-text-primary);
		font-family: var(--v7-font-body);
	}

	.settings-card {
		background: var(--v7-surface-card);
		border-radius: 16px;
		box-shadow:
			0 24px 70px -48px rgba(0, 0, 0, 0.55),
			var(--v7-shadow);
		border: 1px solid var(--v7-border-subtle);
		overflow: hidden;
		margin: 0 auto;
		display: flex;
		flex-direction: column;
		height: 100%;
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
	}

	.settings-header {
		padding: 14px 28px;
		min-height: 76px;
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 16px;
		border-bottom: 1px solid var(--v7-border-subtle);
		flex-shrink: 0;
	}

	.glass-radio-group {
		--bg: rgba(184, 149, 56, 0.08);
		--text: var(--v7-text-secondary);

		display: flex;
		position: relative;
		background: var(--bg);
		border: 1px solid var(--v7-border-subtle);
		border-radius: 1rem;
		backdrop-filter: blur(12px);
		-webkit-backdrop-filter: blur(12px);
		box-shadow:
			inset 1px 1px 4px rgba(255, 255, 255, 0.16),
			inset -1px -1px 6px rgba(0, 0, 0, 0.16),
			0 4px 12px rgba(0, 0, 0, 0.08);
		overflow: hidden;
		width: fit-content;
		max-width: 100%;
	}

	:global(html.dark) .glass-radio-group {
		--bg: rgba(255, 255, 255, 0.06);
	}

	.glass-radio-group input {
		display: none;
	}

	.glass-radio-group label {
		flex: 1 1 0;
		display: flex;
		align-items: center;
		justify-content: center;
		min-width: 118px;
		font-size: 14px;
		padding: 0.8rem 1.25rem;
		cursor: pointer;
		gap: 8px;
		font-weight: 600;
		color: var(--text);
		position: relative;
		z-index: 2;
		white-space: nowrap;
		transition: color 0.3s ease-in-out, text-shadow 0.3s ease-in-out;
	}

	.glass-radio-group label:hover {
		color: var(--v7-text-primary);
	}

	.glass-radio-group input:checked + label {
		color: #fff;
		text-shadow: 0 1px 8px rgba(0, 0, 0, 0.28);
	}

	.glass-glider {
		position: absolute;
		top: 0;
		bottom: 0;
		left: 0;
		width: calc(100% / 3);
		border-radius: 1rem;
		z-index: 1;
		pointer-events: none;
		transition:
			transform 0.5s cubic-bezier(0.37, 1.45, 0.66, 1),
			background 0.4s ease-in-out,
			box-shadow 0.4s ease-in-out;
	}

	.glass-glider.is-app {
		transform: translateX(0%);
		background: linear-gradient(135deg, rgba(184, 149, 56, 0.42), var(--v7-gold-mid));
		box-shadow:
			0 0 18px rgba(184, 149, 56, 0.42),
			0 0 10px rgba(245, 230, 184, 0.35) inset;
	}

	.glass-glider.is-dll {
		transform: translateX(100%);
		background: linear-gradient(135deg, rgba(30, 58, 95, 0.38), var(--v7-gold-bright));
		box-shadow:
			0 0 18px rgba(201, 166, 62, 0.42),
			0 0 10px rgba(214, 228, 240, 0.32) inset;
	}

	.glass-glider.is-maintenance {
		transform: translateX(200%);
		background: linear-gradient(135deg, rgba(184, 40, 40, 0.35), var(--v7-cinnabar));
		box-shadow:
			0 0 18px rgba(184, 40, 40, 0.4),
			0 0 10px rgba(232, 85, 74, 0.32) inset;
	}

	.header-actions {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 10px;
		flex-wrap: wrap;
	}

	.options-content {
		padding: 0 28px 28px;
		min-height: 450px;
		flex-grow: 1;
		overflow-y: auto;
	}

	.group-title {
		font-size: 15px;
		font-weight: 600;
		margin-bottom: 10px;
		color: var(--v7-text-primary);
		display: flex;
		align-items: center;
	}

	.select-with-refresh {
		position: relative;
		width: 100%;
		display: flex;
		align-items: center;
	}

	.refresh-camera-btn{
		margin-left: 10px;
	}

	:deep(.el-collapse) {
		border-top: none;
		border-bottom: none;
	}

	:deep(.el-collapse-item__header) {
		height: 54px;
		font-weight: 600;
		letter-spacing: 0;
	}

	:deep(.el-collapse-item__content) {
		padding-bottom: 12px;
	}

	:deep(.el-form-item__label) {
		color: var(--v7-text-secondary);
		font-weight: 600;
	}

	.config-group {
		margin-bottom: 35px;
	}

	.setting-block,
	.option-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 16px 0;
		border-bottom: 1px solid var(--v7-border-subtle);
		gap: 18px;
	}

	.setting-block {
		display: block;
	}

	.row-text .label {
		font-size: 14px;
		font-weight: 600;
		margin: 0;
		color: var(--v7-text-primary);
	}

	.row-text .sub {
		font-size: 12px;
		color: var(--v7-text-dim);
		margin: 4px 0 0 0;
		line-height: 1.55;
	}

	.row-help {
		font-size: 12px;
		color: var(--v7-text-dim);
		margin: 6px 0 0 0;
		line-height: 1.55;
	}

	.plugin-actions {
		display: flex;
		align-items: center;
		gap: 10px;
		margin-top: 12px;
		flex-wrap: wrap;
	}

	.muted {
		margin-top: 8px;
		color: var(--v7-text-dim) !important;
	}

	.status-danger {
		color: var(--v7-cinnabar-bright);
	}

	.status-success {
		color: var(--v7-jade-bright);
	}

	.slider-info {
		display: flex;
		justify-content: space-between;
		width: 100%;
		margin-bottom: -10px;
	}

	.slider-info .val {
		color: var(--v7-gold-mid);
		font-weight: bold;
	}

	.slider-info .desc {
		font-size: 12px;
		color: var(--v7-text-dim);
	}

	.danger-box {
		background: var(--v7-danger-bg);
		border-radius: 12px;
		padding: 20px;
		border: 1px solid rgba(184, 40, 40, 0.2);
	}

	.danger-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		font-size: 13px;
		color: var(--v7-text-secondary);
		gap: 16px;
	}

	.danger-footer {
		margin-top: 5px;
		font-size: 12px;
		color: var(--v7-cinnabar-bright);
		display: flex;
		align-items: center;
		gap: 5px;
	}

	.red-text {
		color: var(--v7-cinnabar-bright);
	}

	.fade-in {
		animation: fadeIn 0.3s ease-in-out;
	}

	.option-desc {
		background: var(--v7-primary-bg);
		border: 1px solid var(--v7-border-subtle);
		border-radius: 10px;
		padding: 16px;
		margin-top: 20px;
	}

	.option-desc p {
		margin: 6px 0;
		font-size: 13px;
		color: var(--v7-text-secondary);
	}

	.option-desc code {
		background: var(--v7-ink-deep);
		color: var(--v7-gold-pale);
		padding: 2px 6px;
		border-radius: 4px;
		font-size: 12px;
	}

	:deep(.el-alert) {
		border: 1px solid var(--v7-border-subtle);
	}

	:deep(.el-checkbox-group) {
		color: var(--v7-text-secondary);
	}

	@keyframes fadeIn {
		from { opacity: 0; transform: translateY(5px); }
		to { opacity: 1; transform: translateY(0); }
	}

	@media (max-width: 900px) {
		.settings-header {
			align-items: stretch;
			flex-direction: column;
		}

		.glass-radio-group {
			width: 100%;
		}

		.glass-radio-group label {
			min-width: 0;
			padding: 0.72rem 0.75rem;
		}

		.header-actions {
			justify-content: flex-start;
		}
	}

	@media (max-width: 640px) {
		.options-content {
			padding: 0 18px 22px;
		}

		.settings-header {
			padding: 14px 18px;
		}

		.option-row,
		.danger-item {
			align-items: flex-start;
			flex-direction: column;
		}
	}
</style>
