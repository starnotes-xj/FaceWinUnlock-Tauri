<script setup lang="ts">
	import { ref, reactive } from 'vue'
	import { ElMessage, ElMessageBox, ElLoading } from 'element-plus'
	import {
		Unlock,
		Operation,
		VideoCamera,
		InfoFilled,
		Refresh
	} from '@element-plus/icons-vue'
	import { useOptionsStore } from '../stores/options'
	import { invoke } from '@tauri-apps/api/core'
	import { formatObjectString, hashMessage } from '../utils/function'
	import { info, error as errorLog, warn } from '@tauri-apps/plugin-log';
	import { selectCustom } from '../utils/sqlite'
	import { useRouter } from 'vue-router'
	import { openUrl } from '@tauri-apps/plugin-opener';

	// 自启判断
	invoke("check_scheduled_task", {taskName: 'FaceWinUnlockAutoStart'}).then((result)=>{
		config.autoStart = result.data.enable;
	}).catch((error)=>{
		ElMessage.warning(formatObjectString("查询自启状态失败 ", error));
	});

	const optionsStore = useOptionsStore();
	const router = useRouter();

	const activeTab = ref('app')

	const cameraList = ref([]);
	const cameraListLoading = ref(false);
	const autoStartLoading = ref(false);
	const activeNames = ref([]);
	// 解锁服务是否打开了？
	const isServiceRunning = ref(false);
	checkServiceRunning(null);
	const config = reactive({
		camera: optionsStore.getOptionValueByKey('camera') || "-1",
		cameraRotation: parseInt(optionsStore.getOptionValueByKey('cameraRotation')) || 0,
		unlockBrightness: parseInt(optionsStore.getOptionValueByKey('unlockBrightness')) || 0,
		autoStart: true,
		faceRecogDelay: parseFloat(optionsStore.getOptionValueByKey('faceRecogDelay')) || 10.0,
		faceRecogType: optionsStore.getOptionValueByKey('faceRecogType') || 'operation',
		silentRun: optionsStore.getOptionValueByKey('silentRun') ? (optionsStore.getOptionValueByKey('silentRun') == 'false' ? false : true) : false,
		retryDelay: parseFloat(optionsStore.getOptionValueByKey('retryDelay')) || 10.0,
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
	checkAutoFaceRecogOnStart(null);

	const dllConfig = reactive({
		showTile: optionsStore.getOptionValueByKey('showTile') ? (optionsStore.getOptionValueByKey('showTile') == 'false' ? false : true) : true,
		unlockScene: (optionsStore.getOptionValueByKey('unlockScene') || '1,2,4').split(',').map((s: string) => s.trim()).filter(Boolean),
		animationFps: optionsStore.getOptionValueByKey('animationFps') || 'auto'
	})

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
				key: "ANIMATION_FPS",
				value: dllConfig.animationFps // "auto" 或具体数值，DLL 解析失败时自动跟随显示器
			}
		]}).then(()=>{
			return optionsStore.saveOptions({
				showTile: dllConfig.showTile,
				unlockScene: dllConfig.unlockScene.join(','),
				animationFps: dllConfig.animationFps
			})
		}).then((errorArray)=>{
			if(errorArray.length > 0){
				ElMessage.warning({
                    dangerouslyUseHTMLString: true,
                    message: `${result.length} 个配置保存失败: <br />${result.join("<br />")}`
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
			'卸载 DLL和服务 并还原注册表将导致无法在登录界面使用面容解锁。程序将强制回到初始化页面。', 
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
					path: 'FaceWinUnlock-Server.exe', taskName: 'FaceWinUnlockServer', isServer: true, silent: false, runOnSystemStart: true, runImmediately: false
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
				'活体检测准确率低，<font color="red">误判极高，不建议开启</font><br />' +
				'想用活体检测，推荐使用2.2版本<br />' +
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
				<div class="custom-nav">
					<div class="nav-item" :class="{ active: activeTab === 'app' }" @click="activeTab = 'app'">
						<el-icon>
							<Operation />
						</el-icon>
						软件配置
					</div>
					<div class="nav-item" :class="{ active: activeTab === 'dll' }" @click="activeTab = 'dll'">
						<el-icon>
							<Unlock />
						</el-icon>
						系统集成 (DLL)
					</div>
					<div class="nav-item" :class="{ active: activeTab === 'maintenance' }" @click="activeTab = 'maintenance'">
						<el-icon>
							<Tools />
						</el-icon>
						维护与卸载
					</div>
				</div>
				<div>
					<el-button type="primary" size="large" icon="Cpu"
						@click="activeTab === 'dll' ? applyDllSettings() : saveAppConfig()">
						{{ activeTab === 'dll' ? '同步至系统注册表' : '保存本地配置' }}
					</el-button>
					<el-button type="info" plain @click="openUrl('https://github.com/zs1083339604/FaceWinUnlock-Tauri')">Github</el-button>
					<el-button type="danger" plain @click="openUrl('https://gitee.com/lieranhuasha/face-win-unlock-tauri')">Gitee</el-button>
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
									<p style="font-size: 12px; color: #909399; margin: 6px 0 0 0;">
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
									<p style="font-size: 12px; color: #909399; margin: 6px 0 0 0;">
										面容识别期间临时提升屏幕亮度，完成后自动恢复。0 = 不调节；建议 80~100 以改善弱光下解锁成功率。仅支持笔记本内置屏（外接显示器无效）。
									</p>
								</el-form-item>
								<el-form-item label="推理后端">
									<el-select v-model="config.inferenceBackend" style="width: 100%">
										<el-option value="cpu" label="CPU（默认，兼容所有设备）"/>
										<el-option value="opencl" label="GPU - OpenCL（需要支持 OpenCL 的显卡）"/>
										<el-option value="opencl_fp16" label="GPU - OpenCL FP16（更快，支持 FP16 的显卡）"/>
										<el-option value="intel_npu" label="Intel NPU（需要安装 OpenVINO 运行时）"/>
									</el-select>
									<p style="font-size: 12px; color: #909399; margin: 6px 0 0 0;">
										更改后需重新录入人脸或重启识别服务生效。OpenCL/NPU 若加载失败会在录入时报错，请切回 CPU。
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
					
						<el-collapse-item title="活体检测" name="3">
							<!-- 活体检测开关 -->
							<div class="option-row">
								<div class="row-text">
									<p class="label">启用活体检测</p>
									<p class="sub">不推荐开启，准确率不高，想用活体检测，推荐使用2.2版本</p>
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
									<p class="sub">识别到面容后以何种方式对齐人脸</p>
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
											<span v-html="
												config.loginPassword === optionsStore.getOptionValueByKey('loginPassword') ? 
												'<font color=\'red\'>当前为密文</font>' : 
												'<font color=\'green\'>点击保存后加密</font>'">
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
						<div style="padding: 16px 0; border-bottom: 1px solid #f2f6fc;">
							<div class="row-text" style="margin-bottom: 12px;">
								<p class="label">面容识别场景</p>
								<p class="sub">
									选择哪些场景下启用面容解锁。<br />
									UAC / 应用层：支持浏览器查看存储密码、UAC 弹窗等场景，
									<strong>不支持</strong>通行密钥创建时要求的 PIN（该场景为系统 TPM 验证，与密码登录无关）。
								</p>
							</div>
							<el-checkbox-group v-model="dllConfig.unlockScene" style="display: flex; flex-direction: column; gap: 8px;">
								<el-checkbox label="1">登录（开机登录界面）</el-checkbox>
								<el-checkbox label="2">解锁（锁屏解锁界面）</el-checkbox>
								<el-checkbox label="4">UAC / 应用层（浏览器查看密码、UAC 验证等）</el-checkbox>
							</el-checkbox-group>
						</div>
						<div class="option-row">
							<div class="row-text">
								<p class="label">动画刷新率</p>
								<p class="sub">锁屏动画的渲染帧率，"跟随显示器"会自动匹配当前显示器刷新率</p>
							</div>
							<el-select v-model="dllConfig.animationFps" style="width: 160px;">
								<el-option label="跟随显示器" value="auto" />
								<el-option label="30 FPS" value="30" />
								<el-option label="60 FPS" value="60" />
								<el-option label="75 FPS" value="75" />
								<el-option label="120 FPS" value="120" />
								<el-option label="144 FPS" value="144" />
								<el-option label="165 FPS" value="165" />
								<el-option label="240 FPS" value="240" />
							</el-select>
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
	}

	.settings-card {
		background: #fff;
		border-radius: 12px;
		box-shadow: 0 4px 16px rgba(0,0,0,0.04);
		border: 1px solid #e4e7ed;
		overflow: hidden;
		margin: 0 auto;
		display: flex;
		flex-direction: column;
		height: 100%;
	}

	.settings-header {
		padding: 0 30px;
		height: 70px;
		display: flex;
		justify-content: space-between;
		align-items: center;
		border-bottom: 1px solid #f2f6fc;
		flex-shrink: 0;
	}

	.custom-nav {
		display: flex;
		background: #f0f2f5;
		padding: 4px;
		border-radius: 8px;
		gap: 4px;
	}

	.nav-item {
		padding: 8px 20px;
		border-radius: 6px;
		font-size: 14px;
		cursor: pointer;
		display: flex;
		align-items: center;
		gap: 8px;
		transition: all 0.2s;
		color: #606266;
	}

	.nav-item:hover {
		color: #409EFF;
	}

	.nav-item.active {
		background: #fff;
		color: #409EFF;
		box-shadow: 0 2px 6px rgba(0,0,0,0.08);
		font-weight: 600;
	}

	.options-content {
		padding: 0px 30px;
		min-height: 450px;
		flex-grow: 1;
		overflow-y: auto;
	}

	.group-title {
		font-size: 15px;
		font-weight: 600;
		margin-bottom: 10px;
		color: #303133;
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

	.config-group {
		margin-bottom: 35px;
	}

	.option-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 16px 0;
		border-bottom: 1px solid #f2f6fc;
	}

	.row-text .label {
		font-size: 14px;
		font-weight: 500;
		margin: 0;
		color: #2c3e50;
	}

	.row-text .sub {
		font-size: 12px;
		color: #909399;
		margin: 4px 0 0 0;
	}

	.slider-info {
		display: flex;
		justify-content: space-between;
		width: 100%;
		margin-bottom: -10px;
	}

	.slider-info .val {
		color: #409EFF;
		font-weight: bold;
	}

	.slider-info .desc {
		font-size: 12px;
		color: #909399;
	}

	.danger-box {
		background: #fef0f0;
		border-radius: 10px;
		padding: 20px;
		border: 1px solid #fde2e2;
	}

	.danger-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		font-size: 13px;
		color: #606266;
	}

	.danger-footer {
		margin-top: 5px;
		font-size: 12px;
		color: #f56c6c;
		display: flex;
		align-items: center;
		gap: 5px;
	}

	.red-text {
		color: #f56c6c;
	}

	.fade-in {
		animation: fadeIn 0.3s ease-in-out;
	}

	.option-desc {
		background: #f4f4f5;
		border-radius: 8px;
		padding: 16px;
		margin-top: 20px;
	}

	.option-desc p {
		margin: 6px 0;
		font-size: 13px;
		color: #606266;
	}

	.option-desc code {
		background: #e6a23c;
		color: #fff;
		padding: 2px 6px;
		border-radius: 4px;
		font-size: 12px;
	}

	@keyframes fadeIn {
		from { opacity: 0; transform: translateY(5px); }
		to { opacity: 1; transform: translateY(0); }
	}
</style>
