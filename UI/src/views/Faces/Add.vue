<script setup lang="ts">
    import { reactive, ref, onMounted, onActivated, computed, onUnmounted } from 'vue';
    import { ElMessage, ElMessageBox, ElLoading } from 'element-plus';
    import AccountAuthForm from '../../components/AccountAuthForm.vue';
    import { open } from '@tauri-apps/plugin-dialog';
    import { invoke } from '@tauri-apps/api/core';
    import { formatObjectString, removeFace } from '../../utils/function'
    import { openUrl } from '@tauri-apps/plugin-opener';
    import { useRoute, useRouter, onBeforeRouteLeave } from 'vue-router';
    import { info, error as errorLog, warn } from '@tauri-apps/plugin-log';
    import { useFacesStore } from '../../stores/faces';
    import { useOptionsStore } from '../../stores/options';

    const route = useRoute();
    const router = useRouter();
    const facesStore = useFacesStore();
    const optionsStore = useOptionsStore();

    const faceName = ref('');
    const threshold = ref(40);
    // 显示的图片
    const capturedImage = ref('');
    // 这是用来保存的，不要显示
    let rawImageForSystem = '';
    // 是否是摄像头模式
    const isCameraStreaming = ref(false);
    // 是否启用raf循环
    let isLoopRunning = false;
    // 一致性验证模式开关
    const verificationMode = ref(false);
    // 一致性验证模式下的图片
    const verifyingStreamImage = ref('');
    const matchConfidence = ref(0);
    const verifyMessage = ref("");
    const isProcessing = ref(false);
    // 修改时的面容数据，用于最后提交的判断
    let editFaceData = null;
    // 修改面容时，是否修改了图片
    let isEditFaceImage = false;
    const faceDetectionThreshold = ref(90);

    let authForm = reactive({
        accountType: 'local',
        username: '',
        password: '',
        domain: ''
    });

    const isEditMode = computed(() => route.query.mode === 'edit');
    let modelReady = false;
    let modelLoadingPromise: Promise<void> | null = null;

    // 推理后端名称到 OpenCV DNN backend/target ID 的映射
    const INFERENCE_BACKEND_MAP: Record<string, { backend: number; target: number }> = {
        'cpu':         { backend: 0, target: 0 },
        'opencl':      { backend: 3, target: 1 },
        'opencl_fp16': { backend: 3, target: 2 },
        'intel_npu':   { backend: 2, target: 9 },
    };

    async function ensureModelLoaded(showLoading = true) {
        // 不能用 modelReady 早退（issue #12）：本组件被路由 <keep-alive> 缓存，modelReady 会跨导航
        // 保留为 true；而「首选项」页切换推理后端的可用性探测会 unload 后端模型，使 UI 缓存的
        // modelReady 与后端真实状态不同步——此时早退会跳过真正的重新加载，随后 verify_face 读到空
        // 模型报「模型未加载,请先调用load_opencv_model」。改为始终调用 load_opencv_model（后端幂等：
        // 已加载则秒级短路），让后端成为模型加载状态的唯一事实来源。
        if (modelLoadingPromise) return modelLoadingPromise;

        const loadingInstance = showLoading
            ? ElLoading.service({ fullscreen: true, text: '正在加载人脸识别模型...' })
            : null;
        modelLoadingPromise = (async () => {
            try {
                const backendKey = optionsStore.getOptionValueByKey('inferenceBackend') || 'cpu';
                const { backend, target } = INFERENCE_BACKEND_MAP[backendKey] ?? { backend: 0, target: 0 };
                const loadResult: any = await invoke('load_opencv_model', { backend, target });
                modelReady = true;
                // 所选推理后端不可用（如 Intel NPU 缺少 OpenVINO 运行时）时已自动回退到 CPU，
                // 在此明确告知用户，避免误以为仍在使用所选后端 (issue #125)。
                if (loadResult && loadResult.fell_back) {
                    warn(`推理后端不可用，已自动回退到 CPU：${loadResult.fallback_reason || ''}`);
                    ElMessage.warning('所选推理后端不可用（Intel NPU 需安装 OpenVINO 运行时），已自动回退到 CPU。');
                }
            } catch (error) {
                if (showLoading) {
                    ElMessage.error(formatObjectString("加载OpenCV模型失败：", error));
                }
                throw error;
            } finally {
                loadingInstance?.close();
                modelLoadingPromise = null;
            }
        })();

        return modelLoadingPromise;
    }

    // 重置录入表单 / 图片状态。本组件被 <keep-alive> 缓存，进入「添加新面容」时必须清掉上一次录入
    // 残留的图片与表单（issue #20：上一次添加的图片不销毁）。
    function resetEnrollForm() {
        capturedImage.value = '';
        rawImageForSystem = '';
        isEditFaceImage = false;
        verificationMode.value = false;
        verifyingStreamImage.value = '';
        matchConfidence.value = 0;
        verifyMessage.value = '';
        isProcessing.value = false;
        editFaceData = null;
        faceName.value = '';
        threshold.value = 40;
        faceDetectionThreshold.value = 90;
        authForm.accountType = 'local';
        authForm.username = '';
        authForm.password = '';
        authForm.domain = '';
    }

    // 页面出现时就做不涉及隐私采集的准备：后台加载模型，并让 Unlock 服务释放锁屏预热
    // 摄像头。真正打开硬件仍只发生在用户点击“从摄像头抓拍”之后。
    function prepareEnrollmentResources() {
        invoke('prepare_camera_for_ui').catch((error) => {
            warn(`提前让出摄像头失败，将在点击抓拍时重试：${formatObjectString(error)}`);
        });
        void ensureModelLoaded(false).catch((error) => {
            warn(`后台预加载人脸模型失败，将在点击抓拍时重试：${formatObjectString(error)}`);
        });
    }

    // 按当前路由初始化本页：先清空残留，再按 编辑/新增 分别载入。onMounted 与 onActivated（再次进入）
    // 共用，确保 <keep-alive> 缓存下每次进入都是干净且与当前路由一致的状态（issue #20）。用 route.query
    // 现取（不缓存 id），使编辑不同面容 / 新增 之间切换也能正确刷新。
    async function initForRoute() {
        resetEnrollForm();
        prepareEnrollmentResources();
        if (route.query.mode === 'edit') {
            editFaceData = facesStore.getFaceById(route.query.id);
            if (editFaceData) {
                authForm.username = editFaceData.user_name;
                authForm.password = editFaceData.user_pwd;
                authForm.accountType = editFaceData.account_type;
                authForm.domain = editFaceData.json_data.domain || '';
                faceName.value = editFaceData.json_data.alias;
                threshold.value = editFaceData.json_data.threshold;
                faceDetectionThreshold.value = editFaceData.json_data.faceDetectionThreshold * 100;
                try {
                    await ensureModelLoaded();
                    await loadFaceFormPath(localStorage.getItem("exe_dir") + "\\faces\\" + editFaceData.face_token + ".faceimg");
                } catch (error) {
                    const info = formatObjectString("载入图片失败：", error);
                    errorLog(info);
                    ElMessage.error(info);
                }
            } else {
                ElMessage.warning('未找到该人脸数据');
                router.push('/faces');
            }
        } else {
            invoke('get_now_username').then((data) => {
                if (data.code == 200) {
                    authForm.username = data.data.username;
                }
            });
        }
    }

    onMounted(async () => {
        await initForRoute();
    });

    // <keep-alive> 缓存本组件：再次进入时 onMounted 不再触发，若不重置，上一次录入的图片/表单会残留
    // （issue #20）。首次挂载已由 onMounted 处理，用 flag 跳过以避免重复初始化。
    let addPageActivatedOnce = false;
    onActivated(async () => {
        if (!addPageActivatedOnce) {
            addPageActivatedOnce = true;
            return;
        }
        try { await stopCamera(); } catch (_) {}
        isCameraStreaming.value = false;
        await initForRoute();
    });

    onUnmounted(async ()=>{
        await stopCamera();
        if (modelReady) {
            try {
                await invoke('unload_model');
            } catch (error) {
                ElMessage.error(formatObjectString("卸载模型失败：", error));
            }
        }
    })

    // 离开录入页（含顶栏「返回」按钮 $router.back()、任意路由跳转）时务必停掉摄像头 +
    // 一致性验证循环：页面被 <keep-alive> 缓存、onUnmounted 在导航时不触发，返回按钮又在
    // MainLayout 里不经过本组件，故用路由守卫兜底——否则点返回后摄像头灯常亮、验证继续跑（用户反馈）。
    onBeforeRouteLeave(async () => {
        // 即使用户没有点击抓拍，也要用 ui_done 解除进入页面时申请的摄像头让位。
        try { await stopCamera(); } catch (_) {}
        isCameraStreaming.value = false;
        verifyingStreamImage.value = '';
    })

    const handleSelectFile = async () => {
        try {
            localStorage.setItem("proactiveOutOfFocus", "true");
            const selected = await open({
                multiple: false,
                directory: false,
                filters: [{ name: '图片文件', extensions: ['jpg', 'jpeg', 'png'] }]
            });

            if (!selected) return; 

            isProcessing.value = true;
            await ensureModelLoaded();
            
            await loadFaceFormPath(selected);

            isEditFaceImage = true;
        } catch (error) {
            const info = formatObjectString("文件选择失败：", error);
            errorLog(info);
            ElMessage.error(info);
        } finally {
            isProcessing.value = false;
            localStorage.setItem("proactiveOutOfFocus", "false");
        }
    };

    async function loadFaceFormPath(path){
        const result = await invoke("check_face_from_img", { imgPath: path, faceDetectionThreshold: getFaceDetectionThresholdValue() });
            
        capturedImage.value = result.data.display_base64;
        rawImageForSystem = result.data.raw_base64;

        ElMessage.success('图片载入成功');
    }

    const startCamera = async () => {
        if (isProcessing.value) return;
        isProcessing.value = true;
        let cameraIndex = parseInt(optionsStore.getOptionValueByKey("camera"));
        if(isNaN(cameraIndex)){
            cameraIndex = 0;
        }
        try {
            // 模型加载(~3-4s)与摄像头打开(~2-3s MSMF)无依赖，并行执行避免串行等待
            // （issue #3：面容管理抓拍/一致性验证等约 7 秒 → ~4 秒）。
            await Promise.all([
                ensureModelLoaded(),
                invoke("open_camera", { backend: null, camearIndex: cameraIndex }),
            ]);
            isCameraStreaming.value = true;
            isLoopRunning = true;
            streamLoop();
        } catch (error) {
            const info = formatObjectString("摄像头开启失败：", error);
            errorLog(info);
            ElMessage.error(formatObjectString(error));
        } finally {
            isProcessing.value = false;
        }
    };

    const streamLoop = async () => {
        if (!isLoopRunning) return;

        try {
            const cameraRotation = parseInt(optionsStore.getOptionValueByKey('cameraRotation')) || 0;
            if(!verificationMode.value){
                // 面容录入
                const res = await invoke('check_face_from_camera', {faceDetectionThreshold: getFaceDetectionThresholdValue(), cameraRotation});
                if(res.data.display_base64 === "未检测到人脸"){
                    capturedImage.value = res.data.raw_base64;
                    rawImageForSystem = "";
                } else {
                    capturedImage.value = res.data.display_base64;
                    rawImageForSystem = res.data.raw_base64;
                }
            } else {
                // 一致性对比
                const res = await invoke('verify_face', {
                    referenceBase64: rawImageForSystem.split(',')[1],
                    faceDetectionThreshold: getFaceDetectionThresholdValue(),
                    livenessEnabled: optionsStore.getOptionValueByKey('livenessEnabled') ? (optionsStore.getOptionValueByKey('livenessEnabled') == 'false' ? false : true) : false,
                    livenessThreshold: parseFloat(optionsStore.getOptionValueByKey('livenessThreshold')) || 0.50,
                    faceAlignedType: optionsStore.getOptionValueByKey('faceAlignedType') || 'default',
                    cameraRotation,
                });
                if(res.data.display_base64) {
                    verifyingStreamImage.value = res.data.display_base64;
                }

                const isSuccess = res.data.success;
                if(!isSuccess){
                    matchConfidence.value = 0;
                    verifyMessage.value = res.data.message || "验证失败";
                }else{
                    const rawScore = res.data.score;
                    if (rawScore > 0) {
                        matchConfidence.value = Math.floor(Math.min(100, (rawScore / 1.0) * 100));
                    } else {
                        matchConfidence.value = 0;
                    }
                }
            }

            // 帧间延迟：验证模式33ms（~30fps），录入模式50ms（~20fps）（#121）
            const frameDelay = verificationMode.value ? 33 : 50;
            await new Promise(resolve => setTimeout(resolve, frameDelay));

            // 继续下一帧
            requestAnimationFrame(streamLoop);
        } catch (error) {
            // 识别循环出错。常见根因：切到 GPU(OpenCL) 推理后端后模型加载慢/推理异常，
            // 或切走页面时已卸载模型/摄像头（issue #3）。停止循环避免半死状态与反复弹窗，
            // 并给出可操作的提示而非裸露的内部错误。
            isLoopRunning = false;
            const raw = formatObjectString("一致性检查/识别循环出错：", error);
            errorLog(raw);
            const text = String(error ?? '');
            if (text.includes('模型未加载') || text.includes('摄像头未打开')) {
                ElMessage.error('人脸识别未就绪（模型或摄像头未准备好）。若你切换过 GPU（OpenCL）推理后端，部分设备会出现此问题，建议在「首选项 → 识别参数」把推理后端改回 CPU 后重试。');
            } else {
                ElMessage.error(raw);
            }
        }
    };

    const confirmCapture = () => {
        if(!rawImageForSystem || !isCameraStreaming.value){
            ElMessage.warning("人脸数据不正确，无法保存，尝试拉低检测灵敏度。")
            return;
        }

        stopCamera().then(()=>{
            if(capturedImage.value && rawImageForSystem){
                isEditFaceImage = true;
            }

            isCameraStreaming.value = false;
        }).catch(()=>{});
    };

    const stopCapture = () => {
        stopCamera().then(()=>{
            isCameraStreaming.value = false;
            capturedImage.value = '';
            rawImageForSystem = '';
        }).catch(()=>{});
    };

    function stopCamera(){
        isLoopRunning = false;
        verificationMode.value = false;
        return new Promise((resolve, reject) => {
            invoke("stop_camera").then(()=>{
                resolve();
            }).catch((error)=>{
                const info = formatObjectString("摄像头关闭失败：", error);
                errorLog(info);
                ElMessage.error(info);
                reject();
            });
        })
    }

    async function leaveFacePage() {
        try {
            await stopCamera();
        } catch (_) {
            // stopCamera already reports the close failure; navigation should not be blocked.
        }
        verifyingStreamImage.value = '';
        router.push('/faces');
    }

    // 切换验证模式
    const toggleVerification = async () => {
        if (verificationMode.value) {
            verificationMode.value = false;
            stopCamera().then(()=>{
                verifyingStreamImage.value = '';
            }).catch(()=>{});
            return;
        }

        verificationMode.value = true;
        isProcessing.value = true;
        try {
            let cameraIndex = parseInt(optionsStore.getOptionValueByKey("camera"));
            if(isNaN(cameraIndex)){
                cameraIndex = 0;
            }
            // 模型加载与摄像头打开并行（issue #3：一致性验证等约 7 秒 → ~4 秒）
            await Promise.all([
                ensureModelLoaded(),
                invoke("open_camera", { backend: null, camearIndex: cameraIndex }),
            ]);
            isLoopRunning = true;
            streamLoop();
        } catch (error) {
            verificationMode.value = false;
            const info = formatObjectString("摄像头开启失败：", error);
            errorLog(info);
            ElMessage.error(info);
        } finally {
            isProcessing.value = false;
        }
    };

    const handleSave = async () => {
        // 保存前先结束一致性验证 / 摄像头抓拍循环：避免与 save_face_registration 争用摄像头+模型
        // 导致存不了；也让「确认修改/保存」在验证或抓拍进行中点击时先停掉再保存（用户反馈：
        // 点确认更改要能取消验证并保存；从摄像头重新拍摄后也要能直接保存）。
        const wasCapturing = isCameraStreaming.value && !verificationMode.value;
        if (isLoopRunning || isCameraStreaming.value || verificationMode.value) {
            try { await stopCamera(); } catch (_) {}
            isCameraStreaming.value = false;
            verifyingStreamImage.value = '';
        }
        // 直接从摄像头实时流保存 = 使用刚抓拍的新图片
        if (wasCapturing && rawImageForSystem) {
            isEditFaceImage = true;
        }

        if (!authForm.username || !authForm.password) {
            ElMessage.warning('请填写完整的账号密码信息')
            return;
        }

        if (!rawImageForSystem) {
            ElMessage.warning('请先录入面容图片');
            return;
        }

        // 判断置信度是否在合理的范围内
        try {
            let messageBoxText = null;
            if(threshold.value < 36){
                messageBoxText = '置信度小于OpenCV推荐的 36%，误判为同一人的可能性很高，是否继续？'
            } else if(threshold.value > 85) {
                messageBoxText = '置信度过高可能会导致误判，是否继续？'
            }

            if(messageBoxText){
                await ElMessageBox.confirm(messageBoxText, '警告',{
                    confirmButtonText: '继续',
                    cancelButtonText: '取消',
                    type: 'warning',
                });
            }
            
        } catch (error) {
            return;
        }
    
        if(isEditMode.value){
            // 如果是修改，判断数据是否完全一致
            if(
                authForm.username == editFaceData.user_name &&
                authForm.password == editFaceData.user_pwd &&
                authForm.accountType == editFaceData.account_type &&
                authForm.domain == (editFaceData.json_data.domain || '') &&
                faceName.value == editFaceData.json_data.alias &&
                threshold.value == editFaceData.json_data.threshold &&
                getFaceDetectionThresholdValue() == editFaceData.json_data.faceDetectionThreshold &&
                !isEditFaceImage
            ){
                // 没有任何变化，直接成功
                ElMessage.success('修改成功！');
                await leaveFacePage();
                return;
            }
        }

        isProcessing.value = true;

        let face_token = "";

        if(isEditMode.value && !isEditFaceImage){
            // 如果编辑模式中，没有修改图片，则不用重新存储面容特征
            face_token = editFaceData.face_token;
        }else{
            // 如果非编辑模式，或者编辑模式修改了图片
            try {
                const result = await invoke("save_face_registration", {name: faceName.value || '', referenceBase64: rawImageForSystem.split(',')[1], faceDetectionThreshold: getFaceDetectionThresholdValue()});
                face_token = result.data.file_name;
            } catch (error) {
                const info = formatObjectString("存储面容失败：", error);
                errorLog(info);
                ElMessage.error(info);
                isProcessing.value = false;
                return;
            }
        }

        try {

            if(!isEditMode.value){
                await facesStore.addFace({
                    "user_name": authForm.username,
                    "user_pwd": authForm.password,
                    "account_type": authForm.accountType,
                    "face_token": face_token,
                    "json_data": JSON.stringify({
                        threshold: threshold.value,
                        alias: faceName.value || '',
                        view: true, // 默认可见
                        lock: false, // 默认不锁
                        domain: authForm.accountType === 'domain' ? (authForm.domain || '.') : (authForm.accountType === 'online' ? '' : '.'),
                        faceDetectionThreshold: getFaceDetectionThresholdValue()
                    })
                });
            } else {
                await facesStore.editFace({
                    "user_name": authForm.username,
                    "user_pwd": authForm.password,
                    "account_type": authForm.accountType,
                    "face_token": face_token,
                    "json_data": JSON.stringify({
                        threshold: threshold.value,
                        alias: faceName.value || '',
                        view: editFaceData.json_data.view != undefined ? editFaceData.json_data.view : true,
                        lock: editFaceData.json_data.lock != undefined ? editFaceData.json_data.lock : false,
                        domain: authForm.accountType === 'domain' ? (authForm.domain || '.') : (authForm.accountType === 'online' ? '' : '.'),
                        faceDetectionThreshold: getFaceDetectionThresholdValue()
                    })
                }, editFaceData.id);

                if(isEditFaceImage){
                    // 如果信息存储完成，并且修改了图片，删除旧的面容特征
                    // 删除不成功，也不影响使用，所以不用退出
                    removeFace(editFaceData.face_token, "删除旧面容");
                }
            }
            
            info(`${authForm.username} 面容${isEditMode.value ? '修改' : '添加'}成功！`);
            ElMessage.success(isEditMode.value ? '修改成功' : '添加成功');
            await leaveFacePage();
        } catch (error) {
            // 如果失败 删除上面生成的面容图片和特征文件
            removeFace(face_token);
            ElMessage.error(error);
        } finally {
            isProcessing.value = false;
        }
    };

    // 处理 faceDetectionThreshold 的值，确保 / 100 在2位小数之间
    // JS的除法真的不敢恭维，太不靠谱了
    function getFaceDetectionThresholdValue(){
        return parseFloat((faceDetectionThreshold.value / 100).toFixed(2));
    }
</script>

<template>
    <div class="face-add-container">
        <el-row :gutter="24">
            <el-col :span="14">
                <el-card class="visual-card" shadow="never">
                    <div class="display-container" :class="{ 'split-view': verificationMode }">

                        <div class="screen-box primary-screen">
                            <div class="screen-label">{{ verificationMode ? '参考底库' : '采集预览' }}</div>
                            <div v-if="!capturedImage" class="placeholder-content">
                                <el-icon :size="48">
                                    <UserFilled />
                                </el-icon>
                                <p>待录入面容</p>
                            </div>
                            <img v-else :src="capturedImage" class="result-img" :class="{ 'mirrored': isCameraStreaming }" />
                        </div>

                        <div v-if="verificationMode" class="screen-box secondary-screen">
                            <div class="screen-label">实时验证流</div>
                            <div class="scanner-line"></div>
                            <div v-if="!verifyingStreamImage" class="camera-stream-mock">
                                <el-icon :size="48" class="is-loading">
                                    <Loading />
                                </el-icon>
                            </div>
                            <img v-else :src="verifyingStreamImage" class="result-img mirrored" />
                            <div class="confidence-tag" :class="matchConfidence > (threshold) ? 'match' : 'mismatch'">
                                <template v-if="matchConfidence > 0">
                                    <span v-if="matchConfidence > (threshold)">匹配成功</span>
                                    <span v-else>匹配失败</span>
                                    ：置信度 {{ matchConfidence }}%
                                </template>
                                <template v-else>
                                    {{ verifyMessage }}
                                </template>
                            </div>
                        </div>
                    </div>

                    <div class="action-bar">
                        <div class="detection-config">
                            <span class="label">检测灵敏度</span>
                            <el-slider 
                                v-model="faceDetectionThreshold" 
                                :min="10" 
                                :max="100" 
                                size="small"
                            />
                            <el-tooltip content="控制摄像头识别出人脸的难易程度" placement="top">
                                <el-icon :size="14" style="margin-left: 5px; cursor: help;"><QuestionFilled /></el-icon>
                            </el-tooltip>
                        </div>
                        <div class="capture-controls" v-if="!verificationMode">
                            <template v-if="!isCameraStreaming">
                                <el-button 
                                    type="primary" 
                                    plain 
                                    icon="Picture" 
                                    @click="handleSelectFile"
                                    :loading="isProcessing"
                                >
                                    选择本地照片
                                </el-button>
                                <el-button type="primary" @click="startCamera" :loading="isProcessing">从摄像头抓拍</el-button>
                            </template>
                            <template v-else>
                                <el-button type="success" icon="Check" @click="confirmCapture">确认抓拍</el-button>
                                <el-button type="danger" plain icon="Close" @click="stopCapture">取消</el-button>
                            </template>
                        </div>

                        <div class="verify-controls" v-else>
                            <el-tag type="info" effect="plain">正在进行一致性验证...</el-tag>
                        </div>

                        <el-button v-if="capturedImage && !isCameraStreaming" :type="verificationMode ? 'danger' : 'warning'"
                            @click="toggleVerification">
                            {{ verificationMode ? '停止验证' : '一致性验证' }}
                        </el-button>
                    </div>
                </el-card>
            </el-col>

            <el-col :span="10">
                <el-card shadow="never">
                    <template #header><span class="font-bold">底库配置</span></template>
                    <el-form label-position="top">
                        <el-form-item label="面容别名">
                            <el-input v-model="faceName" placeholder="如：XX设备录入" />
                        </el-form-item>

                        <el-form-item label="判定阈值 (置信度)">
                            <div class="slider-box">
                                <el-slider v-model="threshold" :min="20" :max="100" style="width: 100%;"/>
                                <el-tooltip
                                    content="<span>OpenCV 官网建议 <strong>≥ 0.363</strong> (约 <strong>36%</strong>) <br />单击以打开 OpenCV 文档</span>"
                                    placement="top-end"
                                    raw-content
                                >
                                    <el-icon class="question-icon" @click="openUrl('https://docs.opencv.org/4.x/d0/dd4/tutorial_dnn_face.html')"><QuestionFilled /></el-icon>
                                </el-tooltip>
                            </div>
                            <!-- 26-01-04 感觉tip占用空间点有大，尽量让内容在一屏中 -->
                            <!-- <div class="tip">
                                当前阈值: <b style="color: var(--v7-text-secondary); margin: 0 4px;">{{ threshold }}%</b>
                                <span @click="openUrl('https://docs.opencv.org/4.x/d0/dd4/tutorial_dnn_face.html')">
                                    OpenCV 官网建议 ≥ 0.363 (约 36%)
                                </span>
                            </div> -->
                        </el-form-item>

                        <el-divider>关联系统账户</el-divider>
                        <AccountAuthForm v-model="authForm" :small="true" :customTips="'请输入系统密码或微软账号密码，<span style=&quot;color: var(--v7-cinnabar-bright);&quot;>程序不支持 PIN</span><br/>此密码仅用于 DLL 调起 WinLogon 认证<br />不会上传至任何云端<br />注意：<strong>当前使用明文存储</strong>'"/>

                        <div class="footer-btns">
                            <el-button type="success" size="large" @click="handleSave" :disabled="!capturedImage" :loading="isProcessing">
                                {{ isEditMode ? '确认修改' : '保存并录入系统' }}
                            </el-button>
                        </div>
                    </el-form>
                </el-card>
            </el-col>
        </el-row>
    </div>
</template>

<style scoped>
    /* ====== 整体容器 ====== */
    .face-add-container { font-family: var(--v7-font-body); }

    /* ====== 显示容器 ====== */
    .display-container {
        display: flex;
        gap: 10px;
        height: 320px;
        background: var(--v7-ink-char);
        border-radius: 12px;
        overflow: hidden;
        transition: all 0.3s ease;
        border: 1px solid var(--v7-border-subtle);
    }

    .screen-box {
        flex: 1;
        position: relative;
        display: flex;
        justify-content: center;
        align-items: center;
        background:
          radial-gradient(ellipse at center, rgba(201,166,62,.04) 0%, transparent 70%),
          var(--v7-ink-deep);
        border: 1px solid var(--v7-border-subtle);
        border-radius: 8px;
    }

    .screen-label {
        position: absolute;
        top: 10px;
        left: 10px;
        background: rgba(10,10,12,0.8);
        color: var(--v7-gold-bright);
        padding: 3px 10px;
        font-size: 12px;
        border-radius: 6px;
        z-index: 5;
        border: 1px solid var(--v7-border-subtle);
        font-weight: 600;
    }

    .result-img {
        max-width: 100%;
        max-height: 100%;
        object-fit: contain;
        filter: drop-shadow(0 0 10px rgba(201,166,62,0.15));
    }

    .mirrored {
        transform: scaleX(-1);
    }

    .placeholder-content {
        color: var(--v7-text-dim);
        text-align: center;
    }
    .placeholder-content .el-icon {
        color: var(--v7-text-muted);
    }

    /* ====== 验证模式 ====== */
    .split-view .screen-box {
        flex: 0 0 calc(50% - 5px);
    }

    .camera-stream-mock {
        width: 100%;
        height: 100%;
        display: flex;
        justify-content: center;
        align-items: center;
        color: var(--v7-gold-bright);
    }

    .scanner-line {
        position: absolute;
        width: 100%;
        height: 2px;
        background: linear-gradient(90deg, transparent, rgba(201,166,62,.5), var(--v7-gold-bright), rgba(201,166,62,.5), transparent);
        box-shadow: 0 0 16px rgba(201,166,62,.4);
        animation: scan 2s infinite ease-in-out;
        z-index: 2;
    }

    .confidence-tag {
        position: absolute;
        bottom: 16px;
        padding: 6px 16px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        backdrop-filter: blur(8px);
    }

    .match {
        background: rgba(91,140,90,.7);
        color: #e8f5e9;
        border: 1px solid rgba(123,198,126,.4);
    }

    .mismatch {
        background: rgba(194,53,49,.7);
        color: #fde8e8;
        border: 1px solid rgba(194,53,49,.4);
    }

    /* ====== 控制栏 ====== */
    .detection-config {
        display: flex;
        align-items: center;
        background: var(--v7-surface-card);
        padding: 8px 14px;
        border-radius: 10px;
        gap: 10px;
        width: 100%;
        border: 1px solid var(--v7-border-subtle);
    }

    .detection-config .label {
        font-size: 12px;
        color: var(--v7-text-secondary);
        white-space: nowrap;
        font-weight: 600;
    }

    .action-bar {
        margin-top: 18px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 10px;
    }

    .footer-btns {
        margin-top: 20px;
    }

    /* ====== 表单卡片 ====== */
    :deep(.visual-card), :deep(.el-card) {
        background: var(--v7-surface-card) !important;
        border: 1px solid var(--v7-border-subtle) !important;
        border-radius: 16px !important;
    }

    :deep(.el-card__header) {
        color: var(--v7-text-primary) !important;
        font-weight: 600 !important;
        border-bottom: 1px solid var(--v7-border-subtle) !important;
    }

    :deep(.el-form-item__label) {
        color: var(--v7-text-secondary) !important;
        font-weight: 600;
    }

    :deep(.el-divider__text) {
        color: var(--v7-text-dim);
        background: var(--v7-surface-card);
    }

    /* ====== 提示 ====== */
    .tip {
        font-size: 13px;
        color: var(--v7-text-dim);
        margin-top: 8px;
        display: flex;
        align-items: center;
    }

    .tip span {
        margin-left: 8px;
        color: var(--v7-gold-bright);
        cursor: pointer;
        text-decoration: underline;
        transition: color 0.2s ease;
        text-underline-offset: 3px;
    }

    .tip span:hover {
        color: var(--v7-gold-pale);
        text-decoration: none;
    }

    .slider-box{
        width: 100%;
        display: flex;
        align-items: center;
    }

    .question-icon{
        margin-left: 10px;
        font-size: 16px;
        cursor: pointer;
        color: var(--v7-gold-mid);
    }

    /* ====== 动画 ====== */
    @keyframes scan {
        0% { top: 10%; opacity: .4; }
        25% { top: 90%; opacity: .9; }
        50% { top: 50%; opacity: .3; }
        75% { top: 30%; opacity: .7; }
        100% { top: 10%; opacity: .4; }
    }
</style>
