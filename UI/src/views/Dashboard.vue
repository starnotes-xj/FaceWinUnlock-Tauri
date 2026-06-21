<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { ArrowRight } from '@element-plus/icons-vue';
import { useOptionsStore } from '../stores/options';
import { useFacesStore } from '../stores/faces';
import { useUnlockLog } from '../hook/useUnlockLog';
import { ElMessage } from 'element-plus';
import { invoke } from '@tauri-apps/api/core';
import { formatObjectString } from '../utils/function';

const optionsStore = useOptionsStore();
const facesStore = useFacesStore();
const { queryTodayLogs } = useUnlockLog();

const faceCount = ref(facesStore.faceList.length);
const successCount = ref(0);
const failCount = ref(0);

const systemStatus = ref([
  { name: 'WinLogon 凭据提供程序', desc: '系统登录对接', active: true },
  { name: '解锁核心服务', desc: '', active: false },
  { name: '摄像头传感器', desc: '未配置', active: false },
  { name: '人脸识别模型', desc: 'OpenCV DNN', active: true }
]);

const recentLogs = ref<any[]>([]);

onMounted(async () => {
  // v7 火眼金睛眼周粒子
  const eyeParticlesContainer = document.getElementById('v7EyeParticles');
  if (eyeParticlesContainer) {
    // 眼周粒子从 10 降到 5（issue #4 GPU 优化），火眼金睛观感基本不变。
    for (let i = 0; i < 5; i++) {
      const p = document.createElement('span');
      p.className = 'v7-eye-particle';
      const dur = 3.5 + Math.random() * 3;
      p.style.animationDuration = dur + 's';
      p.style.animationDelay = (-Math.random() * dur) + 's';
      p.style.width = (2 + Math.random() * 3) + 'px';
      p.style.height = p.style.width;
      eyeParticlesContainer.appendChild(p);
    }
  }

  try {
    const result = await queryTodayLogs();
    let s = 0, f = 0;
    result.forEach((item: any) => {
      if (item.is_unlock == 1) { s++; }
      else { f++; }
      recentLogs.value.push({
        time: item.lastTime,
        user: facesStore.getFaceAliasById(item.face_id),
        action: item.is_unlock == 1 ? '面容验证通过' : '未知面容',
        status: item.is_unlock == 1 ? 'success' : 'error'
      });
    });
    successCount.value = s;
    failCount.value = f;
  } catch (error) {
    ElMessage.warning(String(error));
  }

  let tempCameraList = optionsStore.getOptionValueByKey('cameraList');
  let tempCameraIndex = optionsStore.getOptionValueByKey('camera');
  if (tempCameraList && tempCameraIndex) {
    let tempList = JSON.parse(tempCameraList);
    const camera = tempList.find((item: any) => item.capture_index == tempCameraIndex);
    if (camera) {
      systemStatus.value[2].desc = camera.camera_name;
      systemStatus.value[2].active = true;
    }
  }

  invoke("check_process_running").then(() => {
    systemStatus.value[1].desc = '面容认证服务运行中';
    systemStatus.value[1].active = true;
  }).catch((error) => {
    console.warn('[Dashboard] 服务检测失败:', formatObjectString(error));
    systemStatus.value[1].desc = '服务未启动';
    systemStatus.value[1].active = false;
  });
});
</script>

<template>
  <div class="dashboard">
    <!-- ====== Topbar ====== -->
    <header class="dash-topbar">
      <div class="topbar-text">
        <div class="v7-topbar-kicker">DASHBOARD · 仪表盘</div>
        <div class="v7-page-title dash-title">欢迎回来，管理员</div>
        <p class="dash-sub">
          系统当前运行状态：
          <span class="v7-tag v7-tag-jade" style="display:inline-flex;font-size:12px">安全</span>
        </p>
      </div>
      <el-button class="v7-btn-primary" size="large" @click="$router.push('/faces/add')">
        录入新面容
      </el-button>
    </header>

    <!-- ====== Grid 布局 ====== -->
    <div class="dash-grid">
      <!-- ★★★ 火眼金睛 · 宇宙之眼 ★★★ -->
      <div class="v7-card card-eye">
        <div class="card-eye-header">
          <div>
            <div class="card-label">火眼金睛</div>
            <div class="card-desc">墨韵星枢 · 宇宙之眼 · 金环轨道</div>
          </div>
          <span class="v7-tag v7-tag-red">面容识别</span>
        </div>
        <div class="v7-eye-stage">
          <!-- 眼周粒子容器 -->
          <div class="eye-particles" id="v7EyeParticles"></div>

          <div class="v7-eye-orbital">
            <!-- 轨道环 -->
            <div class="v7-orbit-ring r1"></div>
            <div class="v7-orbit-ring r2"></div>
            <div class="v7-orbit-ring r3"></div>
            <div class="v7-orbit-ring r4"></div>

            <!-- 扫描线 -->
            <div class="v7-eye-scan-line"></div>

            <!-- 眼体 -->
            <div class="v7-eye-body">
              <div class="v7-iris-texture"></div>
              <div class="pupil-container">
                <div class="v7-pupil">
                  <div class="v7-pupil-highlight"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 核心服务 -->
      <div class="v7-card card-svc">
        <div class="card-label">核心服务</div>
        <div class="card-desc">后台守护进程</div>
        <div style="margin-top: 16px;">
          <span class="v7-tag v7-tag-jade" v-if="systemStatus[1].active">
            <span class="v7-status-dot" style="width:7px;height:7px"></span> 运行正常
          </span>
          <span class="v7-tag v7-tag-red" v-else>
            <span class="v7-status-dot off" style="width:7px;height:7px"></span> 未启动
          </span>
        </div>
      </div>

      <!-- 守护模式 -->
      <div class="v7-card card-night">
        <div class="card-label">守护模式</div>
        <div class="card-desc">墨色语义已统一<br>面容全天候守护</div>
      </div>

      <!-- 通行密钥版本 -->
      <div class="v7-card card-ver">
        <div class="flex-between" style="height:100%">
          <div>
            <div class="card-label">通行密钥插件</div>
            <div class="v7-ver-num" style="margin-top:8px">0.6.0.0</div>
          </div>
          <el-button class="v7-btn-primary" size="small" @click="$router.push('/options')">
            管理
          </el-button>
        </div>
      </div>

      <!-- 面容库 -->
      <div class="v7-card card-fl">
        <div class="card-label">面容库</div>
        <div class="flex-row" style="margin-top:16px">
          <span class="v7-big-num" style="font-size:42px">{{ faceCount }}</span>
          <span class="card-desc" style="margin-top:0">张已注册</span>
        </div>
      </div>

      <!-- 今日统计 -->
      <div class="v7-card card-fg">
        <div class="card-label">今日识别</div>
        <div class="card-desc">登录前人脸用户验证</div>
        <div class="today-stats" style="margin-top:12px">
          <div class="today-item">
            <span class="today-val" style="color:var(--v7-jade-bright)">{{ successCount }}</span>
            <span class="today-lbl">成功</span>
          </div>
          <div class="today-item">
            <span class="today-val" style="color:var(--v7-cinnabar-bright)">{{ failCount }}</span>
            <span class="today-lbl">拦截</span>
          </div>
        </div>
      </div>

      <!-- 安全场景 -->
      <div class="v7-card card-sec">
        <div class="flex-between">
          <div>
            <div class="card-label">安全场景</div>
            <div class="card-desc">登录 · 解锁 · UAC · 浏览器查看密码</div>
          </div>
          <span class="v7-tag v7-tag-red">人脸优先</span>
        </div>
        <!-- 服务状态列表 -->
        <div class="status-mini-list" style="margin-top: 16px;">
          <div v-for="s in systemStatus" :key="s.name" class="status-mini-row">
            <span :class="['v7-status-dot', !s.active && 'off']" style="width:7px;height:7px"></span>
            <span class="status-mini-name">{{ s.name }}</span>
            <span class="status-mini-desc">{{ s.active ? '就绪' : '故障' }} · {{ s.desc }}</span>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  height: 100%;
  font-family: var(--v7-font-body);
}

/* ====== Topbar ====== */
.dash-topbar {
  position: relative;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 14px;
  padding: 22px 26px;
  border: 1px solid var(--v7-border-subtle);
  border-radius: 18px;
  background:
    linear-gradient(135deg, rgba(201,166,62,.08), transparent 34%),
    linear-gradient(180deg, var(--v7-surface-card), rgba(20,24,35,.52));
  box-shadow: 0 24px 64px -42px rgba(0,0,0,.62), var(--v7-shadow);
  overflow: hidden;
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
}

.topbar-text {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.dash-title {
  font-size: 28px !important;
  margin-bottom: 4px;
}

.dash-sub {
  font-size: 13px;
  color: var(--v7-text-dim);
  margin: 0;
}

/* ====== Grid — 默认三列，宽松布局，文字可换行 ====== */
.dash-grid {
  flex: 1;
  min-height: 0;
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(3, 1fr);
  grid-template-areas:
    "eye eye svc"
    "eye eye night"
    "ver fl  fg"
    "sec sec sec";
}

.card-label {
  font-size: 15px;
  font-weight: 600;
  color: var(--v7-text-primary);
}

.card-desc {
  font-size: 12px;
  color: var(--v7-text-dim);
  margin-top: 2px;
  line-height: 1.5;
}

/* Grid areas — 火眼金睛占据 2/3 宽度 */
.card-eye  { grid-area: eye;  min-height: 280px; max-height: 380px; display: flex; flex-direction: column; }
.card-svc  { grid-area: svc;  }
.card-night { grid-area: night; background: linear-gradient(135deg, rgba(30,58,95,.3), rgba(15,25,45,.5)) !important; }
.card-ver  { grid-area: ver;  }
.card-fl   { grid-area: fl;   }
.card-fg   { grid-area: fg;   background: linear-gradient(135deg, rgba(20,24,35,.4), rgba(30,58,95,.15)) !important; }
.card-sec   { grid-area: sec;  }

/* 卡片内边距紧凑 */
.v7-card {
  padding: 16px 18px !important;
  overflow: visible;
}
.v7-card > * {
  max-width: 100%;
}

/* Card animation delays — 缩短延迟链与时长。
   原 0.6~1s 延迟 + 0.8s 时长：切回仪表盘时（keep-alive 恢复 DOM 会重播 CSS 动画）
   卡片要 ~1.8s 才全部浮现，数据其实已缓存，却显得"加载很慢"。
   改为 0.03~0.18s 延迟 + 0.42s 时长，最后一张约 0.6s 就位，保留逐个浮现观感但顺滑得多。 */
.card-svc   { animation: cardRise .42s cubic-bezier(.16,1,.3,1) .03s backwards; }
.card-night { animation: cardRise .42s cubic-bezier(.16,1,.3,1) .06s backwards; }
.card-ver   { animation: cardRise .42s cubic-bezier(.16,1,.3,1) .09s backwards; }
.card-fl    { animation: cardRise .42s cubic-bezier(.16,1,.3,1) .12s backwards; }
.card-fg    { animation: cardRise .42s cubic-bezier(.16,1,.3,1) .15s backwards; }
.card-sec   { animation: cardRise .42s cubic-bezier(.16,1,.3,1) .18s backwards; }

@keyframes cardRise {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* 火眼金睛 header */
.card-eye-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  position: relative;
  z-index: 1;
  flex-shrink: 0;
}

/* 眼周粒子容器 */
.eye-particles {
  position: absolute;
  inset: -40px;
  pointer-events: none;
}

/* 火眼金睛轨道眼缩小适配 */
.v7-eye-orbital {
  width: 200px !important;
  height: 200px !important;
}

/* ====== 今日统计 ====== */
.today-stats {
  display: flex;
  gap: 20px;
}
.today-item { display: flex; flex-direction: column; align-items: center; }
.today-val { font: 700 26px/1 var(--v7-font-display); }
.today-lbl { font-size: 12px; color: var(--v7-text-dim); margin-top: 2px; }

/* ====== 安全场景状态列表 ====== */
.status-mini-list { display: flex; flex-direction: column; gap: 2px; }
.status-mini-row {
  display: flex; align-items: center; gap: 6px;
  padding: 3px 0; min-width: 0;
}
.status-mini-row + .status-mini-row { border-top: 1px solid var(--v7-border-subtle); }
.status-mini-name { font-size: 12px; color: var(--v7-text-primary); font-weight: 500; white-space: nowrap; }
.status-mini-desc { font-size: 11px; color: var(--v7-text-dim); flex: 1; min-width: 0; }

/* ====== Utility ====== */
.flex-row { display: flex; align-items: center; gap: 10px; min-width: 0; }
.flex-between { display: flex; align-items: center; justify-content: space-between; min-width: 0; gap: 8px; }

/* ====== 底栏 — 简化 ====== */
.dash-botbar {
  border-radius: 14px;
  margin-top: 10px;
  padding: 10px 16px;
  background: linear-gradient(120deg, rgba(30,58,95,.3), rgba(15,25,45,.4));
  border: 1px solid var(--v7-border-subtle);
  backdrop-filter: blur(12px);
  display: flex; align-items: center; gap: 12px;
  flex-wrap: wrap;
  font-size: 11px;
}
.botbar-desc { color: var(--v7-text-dim); flex: 1; min-width: 0; }
.botbar-pal { color: var(--v7-gold-mid); display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
.pal-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }

/* ====== Topbar header 紧凑 ====== */
.dash-topbar {
  padding: 16px 20px !important;
  margin-bottom: 10px !important;
}
.dash-title { font-size: 24px !important; }

/* ====== 响应式：更宽窗口（>1500px）恢复四列 ====== */
@media (min-width: 1500px) {
  .dash-grid {
    grid-template-columns: repeat(4, 1fr);
    grid-template-areas:
      "eye eye svc night"
      "eye eye ver ver"
      "fl  fg  sec sec";
  }
  .card-eye { min-height: 360px; max-height: 480px; }
  .v7-eye-orbital { width: 240px !important; height: 240px !important; }
}

/* ====== 响应式：窄窗口（<1000px）两列 ====== */
@media (max-width: 1000px) {
  .dash-grid {
    grid-template-columns: 1fr 1fr;
    grid-template-areas:
      "eye  eye"
      "svc  night"
      "ver  fl"
      "fg   sec";
  }
  .card-eye { min-height: 240px; max-height: 320px; }
  .v7-eye-orbital { width: 170px !important; height: 170px !important; }
  .dash-topbar { flex-direction: column; gap: 10px; align-items: stretch; }
}

/* ====== 响应式：极窄（<700px）单列 ====== */
@media (max-width: 700px) {
  .dash-grid {
    grid-template-columns: 1fr;
    grid-template-areas: "eye" "svc" "night" "ver" "fl" "fg" "sec";
  }
  .card-eye { min-height: 220px; max-height: 280px; }
}
</style>
