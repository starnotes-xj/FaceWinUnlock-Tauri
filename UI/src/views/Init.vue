<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { invoke } from '@tauri-apps/api/core';
import { useOptionsStore } from "../stores/options";
import AccountAuthForm from '../components/AccountAuthForm.vue';
import { handleLocalAccount, formatObjectString } from '../utils/function';
import { info, error as errorLog, warn } from '@tauri-apps/plugin-log';

const checks = reactive({ camera: false, admin: false, loading: true, admin_msg: '', camera_msg: '' });
const activeStep = ref(0);
const isDeploying = ref(false);
const router = useRouter();
const initialized = ref(false);
const deployProgress = ref(0);
const deployStatus = ref('');
const isFinalizing = ref(false);
const optionsStore = useOptionsStore();
const riskDialogVisible = ref(false);
const passkeyAutoSetupAttempted = ref(false);

const passkeyPlugin = reactive({
  loading: false, installed: false, sampleInstalled: false,
  version: '', bundledVersion: '', updateAvailable: false, available: false,
  osSupported: true,
});

async function refreshPasskeyPluginStatus() {
  passkeyPlugin.loading = true;
  try {
    const result: any = await invoke('get_passkey_plugin_status');
    const status = result?.data || {};
    passkeyPlugin.installed = Boolean(status.installed);
    passkeyPlugin.sampleInstalled = Boolean(status.sample_installed);
    passkeyPlugin.version = status.package?.version || status.sample_package?.version || '';
    passkeyPlugin.bundledVersion = status.bundled_version || '';
    passkeyPlugin.updateAvailable = Boolean(status.update_available);
    passkeyPlugin.available = Boolean(status.msix_available && status.certificate_available);
    // os_supported 缺失（旧后端）时默认 true，保持兼容
    passkeyPlugin.osSupported = status.os_supported !== false;
  } catch (error) {
    warn(formatObjectString('查询 Passkey 插件状态失败：', error));
  } finally { passkeyPlugin.loading = false; }
}

async function setupPasskeyPlugin(options: any = {}) {
  const auto = Boolean(options.auto);
  if (!passkeyPlugin.osSupported) {
    // 第三方 passkey Provider 需 Win11 24H2+；旧系统优雅跳过，绝不弹安装错误
    if (!auto) ElMessage.info('当前系统不支持第三方通行密钥（需 Windows 11 24H2 及以上），已跳过此步骤，不影响面容解锁');
    return;
  }
  let replaceSample = false;
  if (passkeyPlugin.sampleInstalled && !passkeyPlugin.installed) {
    if (auto) { warn('检测到 Contoso 测试插件，自动 Passkey 设置已跳过'); return; }
    try {
      await ElMessageBox.confirm(
        '当前安装的是 Contoso 测试插件。替换后测试插件本地保存的通行密钥会被删除，网站端旧凭据也需要重新注册。确定迁移到正式插件吗？',
        '迁移 Passkey 插件', { type: 'warning', confirmButtonText: '确认迁移', cancelButtonText: '保留测试插件' }
      ); replaceSample = true;
    } catch { return; }
  }
  passkeyPlugin.loading = true;
  try {
    const needsInstall = !passkeyPlugin.installed || passkeyPlugin.updateAvailable || replaceSample;
    if (needsInstall) {
      if (!passkeyPlugin.available) { ElMessage.warning('安装包中缺少 Passkey 插件或签名证书'); return; }
      const result: any = await invoke('install_passkey_plugin', { replaceSample });
      ElMessage.success(result?.msg || 'Passkey 插件已安装');
      await refreshPasskeyPluginStatus();
    }
    await invoke('open_passkey_plugin_setup');
    ElMessage.success('已打开 Passkey 插件注册与启用流程');
  } catch (error) { ElMessage.error(formatObjectString('启动 Passkey 插件设置失败：', error)); }
  finally { passkeyPlugin.loading = false; }
}

async function openPasskeyPluginManager() {
  try { await invoke('open_passkey_plugin_manager'); }
  catch (error) { ElMessage.error(formatObjectString('打开 Passkey 插件管理器失败：', error)); }
}

async function uninstallPasskeyPlugin() {
  // 二选项：保留通行密钥卸载（默认）vs 彻底清除。confirm=保留；cancel=彻底清除；关闭=取消。
  let purge = false;
  try {
    await ElMessageBox.confirm(
      '选择卸载方式：<br/><br/>' +
      '<b>保留通行密钥</b>（推荐）：卸载插件但保留本地通行密钥与私钥，重装/全量更新后可继续使用，无需重新注册。<br/><br/>' +
      '<b>彻底清除</b>：删除插件及所有本地通行密钥、私钥、证书，不可恢复。',
      '卸载 Passkey 插件',
      {
        type: 'warning', dangerouslyUseHTMLString: true,
        confirmButtonText: '保留密钥卸载', cancelButtonText: '彻底清除',
        distinguishCancelAndClose: true, showClose: true,
      }
    );
    purge = false;
  } catch (action) {
    if (action === 'cancel') { purge = true; } else { return; }
  }
  if (purge) {
    try {
      await ElMessageBox.confirm('确定彻底清除？所有本地通行密钥与私钥将永久删除，无法恢复。', '彻底清除确认',
        { type: 'error', confirmButtonText: '确认彻底清除', cancelButtonText: '取消' });
    } catch { return; }
  }
  passkeyPlugin.loading = true;
  try {
    const result: any = await invoke('uninstall_passkey_plugin', { purge });
    ElMessage.success(result?.msg || 'Passkey 插件已卸载');
    await refreshPasskeyPluginStatus();
  } catch (error) { ElMessage.error(formatObjectString('卸载 Passkey 插件失败：', error)); }
  finally { passkeyPlugin.loading = false; }
}

let is_initialized = optionsStore.getOptionByKey('is_initialized');
if (is_initialized.index != -1 && is_initialized.data.val == 'true') { initialized.value = true; }

let authForm = reactive({ username: '', password: '', accountType: 'local', domain: '' });
invoke('get_now_username').then((data: any) => { if (data.code == 200) { authForm.username = data.data.username; } });

async function maybeAutoSetupPasskeyPlugin() {
  if (passkeyAutoSetupAttempted.value) return;
  passkeyAutoSetupAttempted.value = true;
  await refreshPasskeyPluginStatus();
  if (!passkeyPlugin.osSupported) return; // 旧系统不自动尝试安装，避免弹错
  if (passkeyPlugin.sampleInstalled && !passkeyPlugin.installed) return;
  if (passkeyPlugin.installed || passkeyPlugin.available) { await setupPasskeyPlugin({ auto: true }); }
}

const handleNextStep = async () => {
  if (activeStep.value < 3) {
    activeStep.value++;
    if (activeStep.value === 2) { await maybeAutoSetupPasskeyPlugin(); }
  }
};

const performCheck = async () => {
  checks.loading = true;
  try { await invoke('check_admin_privileges'); checks.admin = true; checks.admin_msg = ''; }
  catch (e) { checks.admin = false; checks.admin_msg = String(e); ElMessage.warning('请以管理员身份重新运行程序'); }
  try { await invoke('check_camera_status'); checks.camera = true; checks.camera_msg = ''; }
  catch (e) { checks.camera = false; checks.camera_msg = '未检测到摄像头（VM 环境可忽略）'; }
  if (checks.admin && checks.camera) { ElMessage.success('环境检查通过'); }
  else if (checks.admin) { ElMessage.warning('摄像头不可用，面容识别功能将无法使用'); }
  checks.loading = false;
};

onMounted(() => { performCheck(); refreshPasskeyPluginStatus(); });

const startDeployment = () => {
  if (!checks.admin) { return ElMessage.error('权限不足，无法部署'); }
  riskDialogVisible.value = true;
};

const detectAndSaveCamera = async () => {
  try {
    const result: any = await invoke("get_camera");
    const cameraList = Array.isArray(result.data) ? result.data : [];
    const firstValid = cameraList.find((item: any) => item.is_valid) || cameraList[0];
    await optionsStore.saveOptions({ cameraList: JSON.stringify(cameraList), camera: firstValid ? firstValid.capture_index : "-1" });
    if (firstValid) { checks.camera = true; checks.camera_msg = ''; info(`初始化部署已自动选择摄像头: ${firstValid.camera_name}`); }
    else { checks.camera = false; checks.camera_msg = '未检测到可用摄像头'; }
  } catch (error) { checks.camera = false; checks.camera_msg = '摄像头自动检测失败'; }
};

const confirmDeployment = () => {
  riskDialogVisible.value = false;
  isDeploying.value = true;
  invoke('deploy_core_components').then(async () => {
    await detectAndSaveCamera();
    let progress = 0;
    const timer = setInterval(() => {
      progress += 25; deployProgress.value = progress;
      if (progress >= 100) { clearInterval(timer); isDeploying.value = false; deployStatus.value = 'success'; ElMessage.success('DLL 与注册表配置完成'); }
    }, 400);
  }).catch((error: any) => { isDeploying.value = false; deployStatus.value = 'exception'; errorLog(formatObjectString("部署失败：", error)); ElMessageBox.alert(error, '部署失败', { type: 'error' }); });
};

const finishInit = () => {
  if (!authForm.username || !authForm.password) { return ElMessage.warning('请填写完整的账号密码信息'); }
  ElMessageBox.alert('电脑将进入锁屏界面，5秒后自动解锁。<br>请不要手动解锁!!<br>如果5 秒内未解锁，代表测试失败，请手动解锁。', '通知', {
    confirmButtonText: '确定', dangerouslyUseHTMLString: true,
    callback: (action: any) => {
      if (action === 'confirm') {
        handleLocalAccount(authForm, true);
        isFinalizing.value = true;
        invoke('test_win_logon', { userName: authForm.username, password: authForm.password }).then(() => {
          optionsStore.saveOptions({ is_initialized: 'true' }).then((errorList: any) => {
            if (errorList.length > 0) { ElMessageBox.alert(formatObjectString(errorList), '保存设置失败', { confirmButtonText: '确定' }); }
            else { ElMessage.success('初始化成功'); router.push('/'); }
          });
        }).catch((error: any) => { errorLog(formatObjectString("测试失败：", error)); ElMessageBox.alert(formatObjectString(error), '测试失败', { confirmButtonText: '确定' }); })
        .finally(() => { handleLocalAccount(authForm, false); isFinalizing.value = false; });
      }
    }
  });
};
</script>

<template>
  <div class="init-container">
    <div class="init-card">
      <!-- Header -->
      <div class="init-header">
        <div class="header-left">
          <el-button v-if="initialized" icon="ArrowLeft" circle size="small" @click="$router.back()" class="back-btn" />
          <span class="header-title">系统初始化向导</span>
        </div>
        <span :class="['v7-tag', initialized ? 'v7-tag-jade' : 'v7-tag-gold']">
          {{ initialized ? '已激活' : '待配置' }}
        </span>
      </div>

      <!-- Steps -->
      <div class="steps-wrapper">
        <el-steps :active="activeStep" finish-status="success" align-center>
          <el-step title="环境检测" />
          <el-step title="系统部署" />
          <el-step title="Passkey 插件" />
          <el-step title="账户验证" />
        </el-steps>
      </div>

      <!-- Step Content -->
      <div class="step-content">
        <!-- Step 0: 环境检测 -->
        <div v-if="activeStep === 0" class="step-panel">
          <el-result icon="info" title="准备环境" sub-title="检查摄像头及系统权限">
            <template #extra>
              <div v-if="checks.loading" class="check-loading">
                <el-icon class="is-loading" :size="32"><Loading /></el-icon>
                <p>正在检查环境...</p>
              </div>
              <ul v-else class="check-list">
                <li class="check-item">
                  <span class="check-label">管理员权限：</span>
                  <el-icon :color="checks.admin ? '#67C23A' : '#F56C6C'">
                    <CircleCheckFilled v-if="checks.admin" /><CircleCloseFilled v-else />
                  </el-icon>
                  <span v-if="!checks.admin" class="check-error">{{ checks.admin_msg }}</span>
                </li>
                <li class="check-item">
                  <span class="check-label">摄像头状态：</span>
                  <el-icon :color="checks.camera ? '#67C23A' : '#E6A23C'">
                    <CircleCheckFilled v-if="checks.camera" /><WarningFilled v-else />
                  </el-icon>
                  <span v-if="!checks.camera" class="check-warn">{{ checks.camera_msg }}</span>
                </li>
              </ul>
              <el-button type="primary" @click="handleNextStep" :loading="checks.loading" :disabled="!checks.admin" class="step-btn">
                继续部署
              </el-button>
              <p v-if="!checks.admin && !checks.loading" class="admin-warn">请关闭程序，右键以管理员身份重新运行</p>
            </template>
          </el-result>
        </div>

        <!-- Step 1: 部署 -->
        <div v-if="activeStep === 1" class="step-panel">
          <div class="deploy-box">
            <h3>正在部署 WinLogon 核心组件</h3>
            <p>复制 DLL 到 System32 并修改注册表以启用面容识别支持</p>
            <div class="progress-wrap"><el-progress :percentage="deployProgress" :status="deployStatus as any" /></div>
            <el-button type="danger" :loading="isDeploying" @click="startDeployment" v-if="deployProgress === 0">执行部署</el-button>
            <el-button type="primary" :disabled="deployProgress < 100" @click="handleNextStep">下一步</el-button>
          </div>

          <el-dialog v-model="riskDialogVisible" title="⚠️ 重要用户须知" width="680px" top="3vh" :close-on-click-modal="false">
            <div class="risk-tips">
              <p style="margin-top:0">部署会修改 Winlogon 配置，极端情况可能导致：<b>锁屏后无法解锁</b>、登录黑屏、登录循环。</p>
              <el-divider content-position="left">崩溃后修复（强烈建议拍照留档）</el-divider>
              <div style="display:grid; grid-template-columns:auto 1fr; gap:6px 12px; font-size:13px; line-height:1.6">
                <span style="color:var(--v7-gold-bright);font-weight:700">步骤1</span>
                <span>强制关机 3 次 → 自动修复 → 疑难解答 → 启动设置 → 重启 → <b>F5 安全模式</b></span>
                <span style="color:var(--v7-gold-bright);font-weight:700">步骤2</span>
                <span>删除 <code>%SystemRoot%\System32\FaceWinUnlock-Tauri.dll</code>（即系统盘的 Windows\System32，未必是 C:；或删除注册表 <code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}</code>）</span>
                <span style="color:var(--v7-gold-bright);font-weight:700">步骤3</span>
                <span>重启系统即可恢复正常</span>
              </div>
            </div>
            <template #footer>
              <el-button @click="riskDialogVisible = false">取消</el-button>
              <el-button type="danger" @click="confirmDeployment">我已知晓风险，继续部署</el-button>
            </template>
          </el-dialog>
        </div>

        <!-- Step 2: Passkey -->
        <div v-if="activeStep === 2" class="step-panel">
          <div class="deploy-box">
            <h3>启用官方 Passkey Provider</h3>
            <p>插件创建并持有自己的不可导出密钥，人脸识别只负责用户验证。</p>
            <div class="passkey-alerts">
              <el-alert v-if="!passkeyPlugin.osSupported" type="info"
                title="当前系统无需配置通行密钥"
                description="第三方通行密钥（Passkey）Provider 需 Windows 11 24H2 及以上，当前系统不支持，已自动跳过。这不影响面容解锁，请直接点击下一步。"
                show-icon :closable="false" />
              <el-alert v-else-if="passkeyPlugin.installed"
                :type="passkeyPlugin.updateAvailable ? 'warning' : 'success'"
                :title="`正式插件已安装${passkeyPlugin.version ? '（' + passkeyPlugin.version + '）' : ''}`"
                :description="passkeyPlugin.updateAvailable ? `安装包内有更新版本，点击按钮会先更新再打开启用页面。` : '向导会自动注册插件并打开 Windows 设置页。'"
                show-icon :closable="false" />
              <el-alert v-else-if="passkeyPlugin.sampleInstalled" type="warning"
                title="检测到 Contoso 测试插件"
                description="迁移到正式插件会删除测试插件本地凭据。" show-icon :closable="false" />
              <el-alert v-else type="info"
                title="尚未安装 Passkey 插件"
                description="点击下方按钮后会自动安装、注册插件并打开 Windows 启用页面。" show-icon :closable="false" />
              <div class="passkey-actions">
                <el-button type="primary" :loading="passkeyPlugin.loading"
                  :disabled="!passkeyPlugin.osSupported || ((!passkeyPlugin.installed || passkeyPlugin.updateAvailable) && !passkeyPlugin.available)"
                  @click="setupPasskeyPlugin()">
                  {{ passkeyPlugin.installed ? (passkeyPlugin.updateAvailable ? '更新并打开启用页' : '打开注册/启用流程') : '安装并打开启用页' }}
                </el-button>
                <el-button v-if="passkeyPlugin.installed || passkeyPlugin.sampleInstalled" @click="openPasskeyPluginManager">打开插件管理器</el-button>
                <el-button :loading="passkeyPlugin.loading" @click="refreshPasskeyPluginStatus">刷新状态</el-button>
                <el-button v-if="passkeyPlugin.installed || passkeyPlugin.sampleInstalled" type="danger" :loading="passkeyPlugin.loading" @click="uninstallPasskeyPlugin">卸载插件</el-button>
              </div>
            </div>
            <el-button type="primary" @click="handleNextStep">下一步</el-button>
          </div>
        </div>

        <!-- Step 3: 账户验证 -->
        <div v-if="activeStep === 3" class="step-panel">
          <div class="account-box">
            <AccountAuthForm v-model="authForm"
              custom-tips="请输入系统密码或微软账号密码，<span style='color: var(--v7-cinnabar-bright);'>程序不支持 PIN</span><br />此密码仅用于 DLL 调起 WinLogon 认证" />
            <el-button type="success" style="width: 100%; margin-top: 20px;" @click="finishInit" :loading="isFinalizing">执行最终测试</el-button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.init-container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100%;
}

.init-card {
  width: 100%;
  max-width: 800px;
  max-height: 100%;
  background: var(--v7-surface-card);
  border-radius: 18px;
  border: 1px solid var(--v7-border-subtle);
  box-shadow: 0 24px 64px -36px rgba(0,0,0,.55), var(--v7-shadow);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.init-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 18px 24px;
  border-bottom: 1px solid var(--v7-border-subtle);
}

.header-left { display: flex; align-items: center; gap: 12px; }
.header-title { font: 600 16px/1 var(--v7-font-display); color: var(--v7-text-primary); }

.steps-wrapper { padding: 24px 24px 0; }

.step-content {
  flex: 1;
  min-height: 300px;
  padding: 24px;
  overflow-y: auto;
}

.step-panel { text-align: center; }

.check-loading { margin-bottom: 20px; }
.check-loading p { color: var(--v7-text-dim); margin-top: 8px; }

.check-list { list-style: none; padding: 0; display: inline-block; margin-bottom: 20px; text-align: left; }
.check-item { margin: 10px 0; font-size: 15px; display: flex; align-items: center; gap: 10px; }
.check-label { color: var(--v7-text-secondary); }
.check-error { color: var(--v7-cinnabar-bright); font-size: 13px; margin-left: 4px; }
.check-warn { color: var(--v7-gold-mid); font-size: 13px; margin-left: 4px; }

.step-btn { display: block; width: 200px; margin: 0 auto; }

.admin-warn { color: var(--v7-cinnabar-bright); font-size: 13px; margin-top: 10px; }

.deploy-box { text-align: center; padding: 20px; }
.deploy-box h3 { color: var(--v7-text-primary); font: 600 18px/1 var(--v7-font-display); margin: 0 0 8px; }
.deploy-box p  { color: var(--v7-text-dim); font-size: 13px; margin: 0 0 20px; }

.progress-wrap { margin: 30px 0; }

.passkey-alerts { max-width: 520px; margin: 20px auto; text-align: left; }
.passkey-actions { display: flex; justify-content: center; gap: 10px; margin-top: 16px; flex-wrap: wrap; }

.account-box { max-width: 450px; margin: 0 auto; }

  .risk-tips { font-size: 13px; color: var(--v7-text-primary); line-height: 1.6; }
  .risk-tips code { background: var(--v7-ink-deep); padding: 2px 6px; border-radius: 3px; font-size: 12px; word-break: break-all; }

.back-btn { transition: all .2s; }
.back-btn:hover { background-color: rgba(201,166,62,.08); transform: translateX(-2px); }
</style>
