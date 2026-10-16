<script setup lang="ts">
import { ref, reactive, computed } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { useOptionsStore } from "../stores/options";
import { useFacesStore } from "../stores/faces";
import { hashMessage } from "../utils/function";
import { invoke } from '@tauri-apps/api/core';

const router = useRouter();
const optionsStore = useOptionsStore();
const facesStore = useFacesStore();

const version = ref(localStorage.getItem("version") || 'unknown');
const isLoading = ref(false);
const errorMessage = ref('');
const faceLoginAvailable = computed(() =>
  optionsStore.getOptionValueByKey('loginEnabled') === 'true' &&
  facesStore.faceList.some(face => face.json_data?.lock !== true)
);
const inferenceBackendMap: Record<string, { backend: number; target: number }> = {
  cpu: { backend: 0, target: 0 },
  opencl: { backend: 3, target: 1 },
  opencl_fp16: { backend: 3, target: 2 },
  intel_npu: { backend: 2, target: 9 },
};

const loginForm = reactive({
  password: ''
});

const handleLogin = async () => {
  if (isLoading.value) return;
  if (!loginForm.password) {
    errorMessage.value = '请输入密码';
    return;
  }
  errorMessage.value = '';
  isLoading.value = true;
  try {
    if (optionsStore.getOptionValueByKey('loginPassword') === await hashMessage(loginForm.password)) {
      completeLogin('登录成功');
    } else {
      throw '密码错误，请重试';
    }
  } catch (error) {
    errorMessage.value = typeof error === 'string' ? error : '登录失败，请重试';
  } finally {
    isLoading.value = false;
  }
};

const completeLogin = (message: string) => {
  ElMessage.success(message);
  localStorage.setItem('lastLoginTime', Date.now().toString());
  router.replace('/');
};

const handleFaceLogin = async () => {
  if (isLoading.value) return;
  errorMessage.value = '';
  isLoading.value = true;
  let cameraNeedsRelease = false;
  let authenticated = false;
  try {
    await invoke('prepare_camera_for_ui');
    cameraNeedsRelease = true;
    let cameraIndex = Number.parseInt(optionsStore.getOptionValueByKey('camera'), 10);
    if (Number.isNaN(cameraIndex)) cameraIndex = 0;
    const backendKey = optionsStore.getOptionValueByKey('inferenceBackend') || 'cpu';
    const { backend, target } = inferenceBackendMap[backendKey] ?? inferenceBackendMap.cpu;
    const [modelResult, cameraResult] = await Promise.allSettled([
      invoke('load_opencv_model', { backend, target }),
      invoke('open_camera', { backend: null, camearIndex: cameraIndex }),
    ]);
    if (modelResult.status === 'rejected') throw modelResult.reason;
    if (cameraResult.status === 'rejected') throw cameraResult.reason;
    await new Promise(resolve => window.setTimeout(resolve, 400));

    const cameraRotation = Number.parseInt(optionsStore.getOptionValueByKey('cameraRotation'), 10) || 0;
    const result = await invoke('verify_app_login_face', { cameraRotation });
    if (result?.data?.success !== true) {
      throw result?.data?.message || '人脸验证失败，请重试或使用密码登录';
    }
    authenticated = true;
  } catch (error) {
    errorMessage.value = typeof error === 'string'
      ? error
      : error instanceof Error ? error.message : '人脸解锁失败，请使用密码登录';
  } finally {
    if (cameraNeedsRelease) {
      await invoke('stop_camera').catch(error => console.warn('关闭应用登录摄像头失败', error));
    }
    isLoading.value = false;
  }
  if (authenticated) completeLogin('人脸解锁成功');
};

const handleKeyDown = (e: KeyboardEvent) => {
  if (e.key === 'Enter') handleLogin();
};
</script>

<template>
  <div class="login-container">
    <div class="login-card">
      <!-- 品牌标识 -->
      <div class="login-emblem">
        <div class="v7-emblem" style="width:64px;height:64px">
          <span class="r1"></span>
          <span class="r2"></span>
          <span class="r3"></span>
        </div>
      </div>

      <h1 class="login-title">面容解锁</h1>
      <p class="login-sub">FaceWinUnlock · 墨韵星枢</p>

      <div class="login-form">
        <p class="form-label">应用已锁定，请验证身份</p>

        <el-button
          v-if="faceLoginAvailable"
          type="primary"
          size="large"
          :loading="isLoading"
          @click="handleFaceLogin"
          class="login-btn"
        >
          人脸解锁
        </el-button>

        <p v-if="faceLoginAvailable" class="face-login-hint">请正对摄像头；活体检测通过后即可进入</p>
        <p class="form-label">{{ faceLoginAvailable ? '或输入应用登录密码' : '请输入应用登录密码' }}</p>

        <el-input
          v-model="loginForm.password"
          type="password"
          placeholder="请输入密码"
          show-password
          @keydown="handleKeyDown"
          :disabled="isLoading"
          size="large"
        />

        <div v-if="errorMessage" class="error-message">
          <span class="v7-tag v7-tag-red">{{ errorMessage }}</span>
        </div>

        <el-button
          type="primary"
          size="large"
          :loading="isLoading"
          @click="handleLogin"
          class="login-btn"
        >
          解锁进入
        </el-button>
      </div>

      <div class="login-footer">
        <span class="version">v {{ version }}</span>
        <span class="divider">|</span>
        <span class="seal-text">面容守护</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-container {
  height: 100vh;
  width: 100vw;
  display: flex;
  justify-content: center;
  align-items: center;
  position: relative;
  z-index: 2;
}

.login-card {
  width: 100%;
  max-width: 420px;
  background: var(--v7-surface-card);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border: 1px solid var(--v7-border-subtle);
  border-radius: 24px;
  padding: 42px 38px;
  box-shadow:
    0 0 0 1px rgba(201,166,62,.06),
    0 30px 60px -24px rgba(0,0,0,.55),
    var(--v7-glow-gold);
  display: flex;
  flex-direction: column;
  align-items: center;
  animation: cardRise .8s cubic-bezier(.16,1,.3,1) both;
}

@keyframes cardRise {
  from { opacity: 0; transform: translateY(24px); }
  to   { opacity: 1; transform: translateY(0); }
}

.login-emblem {
  margin-bottom: 16px;
}

.login-title {
  font: 400 28px/1.2 var(--v7-font-display);
  color: var(--v7-text-primary);
  margin: 0 0 4px;
}

.login-sub {
  font: 600 10px/1 var(--v7-font-en);
  letter-spacing: .28em;
  color: var(--v7-gold-mid);
  text-transform: uppercase;
  margin: 0 0 28px;
}

.login-form {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.form-label {
  font-size: 14px;
  color: var(--v7-text-secondary);
  text-align: center;
  margin: 0;
}

.error-message {
  text-align: center;
}

.face-login-hint {
  font-size: 12px;
  color: var(--v7-text-dim);
  text-align: center;
  margin: -8px 0 0;
}

.login-btn {
  width: 100%;
  height: 46px;
  font-size: 16px;
  font-weight: 600;
  border-radius: 12px;
  margin-top: 4px;
}

.login-footer {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 24px;
  padding-top: 16px;
  border-top: 1px solid var(--v7-border-subtle);
  width: 100%;
  justify-content: center;
}

.version {
  font-size: 12px;
  color: var(--v7-text-dim);
}

.divider {
  color: var(--v7-text-muted);
  font-size: 12px;
}

.seal-text {
  font: 400 13px/1 var(--v7-font-seal);
  color: var(--v7-gold-mid);
}
</style>
