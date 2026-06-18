<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage } from 'element-plus';
import { useOptionsStore } from "../stores/options";
import { hashMessage } from "../utils/function";

const router = useRouter();
const optionsStore = useOptionsStore();

const version = ref(localStorage.getItem("version") || 'unknown');
const isLoading = ref(false);
const errorMessage = ref('');

const loginForm = reactive({
  password: ''
});

const handleLogin = async () => {
  if (!loginForm.password) {
    errorMessage.value = '请输入密码';
    return;
  }
  errorMessage.value = '';
  isLoading.value = true;
  try {
    if (optionsStore.getOptionValueByKey('loginPassword') === await hashMessage(loginForm.password)) {
      ElMessage.success('登录成功');
      localStorage.setItem('lastLoginTime', Date.now().toString());
      router.replace('/');
    } else {
      throw '密码错误，请重试';
    }
  } catch (error) {
    errorMessage.value = typeof error === 'string' ? error : '登录失败，请重试';
  } finally {
    isLoading.value = false;
  }
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
        <p class="form-label">请输入应用登录密码</p>

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
