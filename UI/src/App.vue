<script setup>
import { ref, onMounted } from 'vue';
import { RouterView } from 'vue-router';
import { connect } from './utils/sqlite.js';
import { formatObjectString } from './utils/function.js';
import { ElMessage, ElMessageBox } from 'element-plus';
import { useOptionsStore } from "./stores/options";
import { useRouter, useRoute } from 'vue-router';
import { invoke } from '@tauri-apps/api/core';
import { info, warn } from '@tauri-apps/plugin-log';
import { useFacesStore } from './stores/faces.js';
import { attachConsole } from "@tauri-apps/plugin-log";
import { getVersion } from '@tauri-apps/api/app';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';

/* v7 墨韵星枢 · 背景金箔粒子初始化 */
onMounted(() => {
  const particlesContainer = document.getElementById('v7Particles');
  if (particlesContainer) {
    for (let i = 0; i < 24; i++) {
      const p = document.createElement('span');
      p.className = 'v7-particle';
      p.style.left = (Math.random() * 96 + 2) + '%';
      const dur = 14 + Math.random() * 18;
      p.style.animationDuration = dur + 's';
      p.style.animationDelay = (-Math.random() * dur) + 's';
      p.style.width = (1.5 + Math.random() * 2.5) + 'px';
      p.style.height = p.style.width;
      particlesContainer.appendChild(p);
    }
  }
});

const isInit = ref(false);
const router = useRouter();
const route = useRoute();
const optionsStore = useOptionsStore();
const facesStore = useFacesStore();
const currentWindow = getCurrentWindow();

// 打包时注释
attachConsole();

invoke('get_install_dir').then((res)=>{
  const dir = typeof res?.data === 'string' ? res.data : (res?.data ?? '');
  if (!dir) { throw new Error('get_install_dir 返回空'); }
  localStorage.setItem('exe_dir', dir);
  return connect();
}).then(()=>{
  return optionsStore.init();
}).then(async ()=>{
  if (!optionsStore.getOptionValueByKey('cameraList') || !optionsStore.getOptionValueByKey('camera')) {
    try {
      const result = await invoke("get_camera");
      const cameraList = Array.isArray(result.data) ? result.data : [];
      const firstValid = cameraList.find(item => item.is_valid) || cameraList[0];
      await optionsStore.saveOptions({
        cameraList: JSON.stringify(cameraList),
        camera: firstValid ? firstValid.capture_index : "-1"
      });
      if (firstValid) { info(`自动检测并选择摄像头: ${firstValid.camera_name} (${firstValid.capture_index})`); }
    } catch (error) { warn(formatObjectString("自动检测摄像头失败：", error)); }
  }
}).then(()=>{
  return invoke("init_model");
}).then(()=>{
  return facesStore.init();
}).then(async ()=>{
  let is_initialized = optionsStore.getOptionByKey('is_initialized');
  if(is_initialized.index == -1 || is_initialized.data.val != 'true'){
    warn("程序未初始化，强制跳转初始化界面");
    router.replace('/init');
  } else {
    if(optionsStore.getOptionValueByKey("loginEnabled") === "true" &&
      (optionsStore.getOptionValueByKey("loginMethod") === "onlyOpenApp" || optionsStore.getOptionValueByKey("loginMethod") === "showApp")
    ){
      info("登录安全已启用，跳转登录界面");
      router.replace('/login');
    }
  }
  info("程序初始化完成");
  invoke("repair_unlock_scheduled_task").then((result)=>{
    info(`核心服务计划任务自动修复完成: ${JSON.stringify(result?.data ?? {})}`);
  }).catch((error)=>{
    warn(formatObjectString("核心服务计划任务自动修复失败：", error));
  });
  invoke("repair_ui_auto_start_task").then((result)=>{
    info(`UI 自启任务自动修复完成: ${JSON.stringify(result?.data ?? {})}`);
  }).catch((error)=>{
    warn(formatObjectString("UI 自启任务自动修复失败：", error));
  });
  const launchedSilently = await invoke("is_silent_launch").catch(() => false);
  if(!launchedSilently && optionsStore.getOptionValueByKey('silentRun') != "true"){
    currentWindow.isVisible().then((visible) => {
      if(!visible){ currentWindow.show(); }
      currentWindow.setFocus();
    }).catch((error)=>{ warn(formatObjectString("获取窗口状态失败 ",error)); })
  }
  isInit.value = true;

  const appWindow = getCurrentWebviewWindow();
  appWindow.onFocusChanged(({ payload: focused }) => {
    if (focused && optionsStore.getOptionValueByKey("is_initialized") === "true" && localStorage.getItem("proactiveOutOfFocus") !== "true") {
      if(optionsStore.getOptionValueByKey("loginEnabled") === "true" && route.path !== '/login'){
        const loginMethod = optionsStore.getOptionValueByKey("loginMethod");
        let loginLog = false;
        if(loginMethod === "showApp"){ router.replace('/login'); loginLog = true; }
        else if(loginMethod.includes("time:")){
          let time = parseInt(loginMethod.split(":")[1]);
          const lastLoginTime = localStorage.getItem("lastLoginTime") || '0';
          if(Date.now() - parseInt(lastLoginTime) >= time * 60 * 1000){ router.replace('/login'); loginLog = true; }
        } else if(loginMethod !== "onlyOpenApp"){ warn("未知的登录显示方法：" + optionsStore.getOptionValueByKey("loginMethod")); }
        if(loginLog){ info("需要进行登录认证"); }
      }
    }
  });
}).catch((error)=>{
  ElMessageBox.alert(formatObjectString(error), '程序初始化失败', {
    confirmButtonText: '确定',
    callback: () => { invoke("close_app"); }
  });
});

getVersion().then((v)=>{ localStorage.setItem('version', v); });
</script>

<template>
  <!-- ====== v7 背景层：水墨晕染 + 宣纸纹理 ====== -->
  <div class="v7-bg-layer"></div>
  <!-- ====== v7 金箔粒子 ====== -->
  <div class="v7-particles" id="v7Particles"></div>

  <div class="app-wrapper" v-if="isInit">
    <router-view />
  </div>
</template>

<style scoped>
.app-wrapper {
  height: 100vh;
  width: 100vw;
  position: relative;
  z-index: 2;
}
</style>

<style>
.el-message-box__content { user-select: text; }
</style>
