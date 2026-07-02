<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { RouterView, useRouter, useRoute } from 'vue-router';
import { Sunny, Moon, ArrowLeft } from '@element-plus/icons-vue';
import { ElNotification, ElMessageBox, ElLoading, ElMessage } from 'element-plus';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { useTheme } from '../hook/useTheme';

const router = useRouter();
const route = useRoute();
const version = ref(localStorage.getItem("version") || 'unknown');
const checkingUpdate = ref(false);
const { isDark, toggleTheme } = useTheme();

const navItems = [
  { path: '/',        label: '仪表盘' },
  { path: '/faces',   label: '面容管理' },
  { path: '/options', label: '首选项' },
  { path: '/logs',    label: '日志审计' },
];

function navigate(path: string) {
  router.push(path);
}
function isActive(item: any) {
  if (item.path === '/') return route.path === '/';
  return route.path.startsWith(item.path);
}

/* ====== v7 3D 视差效果（rAF 节流）======
   原实现每次 pointermove 都 getBoundingClientRect（强制同步 reflow）+ 写 CSS 变量，
   触发整块 layout-wrapper（backdrop-filter: blur(40px) + preserve-3d）重绘，高频下拖累流畅度。
   改为合并到每帧一次：pointermove 只记录坐标，rAF 回调统一计算并写入，效果不变、开销大降。 */
let frameEl: HTMLElement | null = null;
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
let tiltRaf = 0;
let lastPointer: { x: number; y: number } | null = null;

function applyTilt() {
  tiltRaf = 0;
  if (!frameEl || !lastPointer) return;
  const rect = frameEl.getBoundingClientRect();
  const x = (lastPointer.x - rect.left) / rect.width - 0.5;
  const y = (lastPointer.y - rect.top) / rect.height - 0.5;
  document.documentElement.style.setProperty('--tilt-x', (-y * 3.2).toFixed(2) + 'deg');
  document.documentElement.style.setProperty('--tilt-y', (x * 4.0).toFixed(2) + 'deg');
}

function onPointerMove(e: PointerEvent) {
  if (!frameEl || reducedMotion.matches) return;
  lastPointer = { x: e.clientX, y: e.clientY };
  if (!tiltRaf) tiltRaf = requestAnimationFrame(applyTilt);
}

function onPointerLeave() {
  if (tiltRaf) { cancelAnimationFrame(tiltRaf); tiltRaf = 0; }
  document.documentElement.style.setProperty('--tilt-x', '0deg');
  document.documentElement.style.setProperty('--tilt-y', '0deg');
}

onMounted(() => {
  frameEl = document.querySelector('.layout-wrapper') as HTMLElement;
  if (frameEl && !reducedMotion.matches) {
    frameEl.addEventListener('pointermove', onPointerMove);
    frameEl.addEventListener('pointerleave', onPointerLeave);
  }
});

onUnmounted(() => {
  if (tiltRaf) cancelAnimationFrame(tiltRaf);
  if (frameEl) {
    frameEl.removeEventListener('pointermove', onPointerMove);
    frameEl.removeEventListener('pointerleave', onPointerLeave);
  }
});

function formatUpdateMessage(info: any) {
  return info?.update_reason || `当前 v${info?.current_version} → 最新 v${info?.latest_version}`;
}

async function manualCheckUpdate() {
  checkingUpdate.value = true;
  try {
    const info: any = await invoke('check_update');
    if (info?.has_update) {
      try {
        await ElMessageBox.confirm(
          `${formatUpdateMessage(info)}，是否前往 GitHub 下载页？`,
          '发现新版本',
          { confirmButtonText: '前往下载', cancelButtonText: '稍后', type: 'info' }
        );
        if (info.release_url) openUrl(info.release_url);
      } catch { /* 用户选“稍后” */ }
    } else { ElMessage.success(`已是最新版本 v${info?.current_version || version.value}`); }
  } catch (e) { ElMessage.error('检查更新失败: ' + (e?.toString() || '网络错误')); }
  finally { checkingUpdate.value = false; }
}

onMounted(async () => {
  try {
    const info: any = await invoke('check_update'); if (!info?.has_update) return;
    let diff: any;
    try { diff = await invoke('fetch_update_diff'); } catch {
      try {
        await ElMessageBox.confirm(
          `${formatUpdateMessage(info)}，是否前往 GitHub 下载页？`,
          '发现新版本',
          { confirmButtonText: '前往下载', cancelButtonText: '稍后', type: 'info' }
        );
        if (info.release_url) openUrl(info.release_url);
      } catch {}
      return;
    }
    if (!diff?.files_to_update?.length) return;
    try {
      await ElMessageBox.confirm(
        `${formatUpdateMessage(info)}，需下载 ${diff.files_to_update.length} 个文件（约 ${diff.total_size_mb.toFixed(1)} MB），是否立即更新？`,
        '发现更新', { confirmButtonText: '立即更新', cancelButtonText: '稍后', type: 'info' }
      );
    } catch { return; }
    const loading = ElLoading.service({ fullscreen: true, text: '正在下载更新...' });
    try {
      await invoke('apply_update'); loading.close();
      try {
        await ElMessageBox.confirm('更新已下载，退出软件后自动应用。是否立即退出以完成更新？', '更新完成',
          { confirmButtonText: '立即退出', cancelButtonText: '稍后', type: 'success' });
        await invoke('close_app');
      } catch { ElMessage.info('更新已下载，下次退出软件时自动应用'); }
    } catch (e) { loading.close(); ElMessage.error('更新失败：' + e); }
  } catch { /* 静默 */ }
});

function resetScroll() {
  const el = document.querySelector('.main-content');
  if (el) el.scrollTop = 0;
}
</script>

<template>
  <div class="layout-wrapper">
    <!-- ====== 侧边栏：墨碑 ====== -->
    <aside class="sidebar">
      <!-- 品牌标识 -->
      <div class="brand-block">
        <div class="v7-emblem">
          <span class="r1"></span>
          <span class="r2"></span>
          <span class="r3"></span>
        </div>
        <div class="brand-text">
          <div class="v7-brand-en">FACE GUARD</div>
          <div class="v7-brand-zh">面容解锁</div>
        </div>
      </div>

      <!-- 导航 -->
      <nav class="nav-list">
        <button
          v-for="item in navItems" :key="item.path"
          class="v7-nav-item" :class="{ active: isActive(item) }"
          @click="navigate(item.path)"
        >
          <span class="v7-nav-dot"></span>
          {{ item.label }}
        </button>
      </nav>

      <!-- 底部：守护状态 + 主题切换 + 版本 -->
      <div class="aside-footer">
        <div class="v7-guard">
          <div class="v7-guard-label">守护状态</div>
          <div class="v7-guard-val">
            <span class="v7-status-dot"></span>已就绪
          </div>
        </div>
        <div class="footer-actions">
          <el-button
            :icon="isDark ? Sunny : Moon"
            circle size="small"
            @click="toggleTheme"
            class="theme-btn"
            :title="isDark ? '切换亮色' : '切换暗色'"
          />
          <span class="version-text">v {{ version }}</span>
        </div>
        <el-button size="small" text :loading="checkingUpdate" @click="manualCheckUpdate" class="check-btn">
          {{ checkingUpdate ? '检查中…' : '检查更新' }}
        </el-button>
      </div>

      <!-- 印章 -->
      <div class="v7-sidebar-seal"><span>墨韵星枢</span></div>
    </aside>

    <!-- ====== 主内容区 ====== -->
    <div class="main-area">
      <!-- Topbar -->
      <header class="topbar">
        <div class="topbar-left">
          <el-button v-if="$route.path !== '/'" :icon="ArrowLeft" circle size="small" @click="$router.back()" class="back-btn" />
          <div class="title-stack">
            <span class="v7-topbar-kicker">FACEWINUNLOCK · 墨韵星枢</span>
            <span class="v7-page-title topbar-title-text">{{ $route.meta.title || '面容与通行密钥安全中枢' }}</span>
          </div>
        </div>
        <!-- 顶部旋转八宝纹章 -->
        <div class="topbar-emblem">
          <svg viewBox="-60 -60 120 120" class="emblem-svg">
            <defs>
              <g id="bx8">
                <path d="M0 -18 C12 -34 12 -58 0 -68 C-12 -58 -12 -34 0 -18Z" fill="none" stroke="var(--v7-gold-mid)" stroke-width="1.4"/>
              </g>
            </defs>
            <use href="#bx8" transform="rotate(0)"/>
            <use href="#bx8" transform="rotate(45)"/>
            <use href="#bx8" transform="rotate(90)"/>
            <use href="#bx8" transform="rotate(135)"/>
            <use href="#bx8" transform="rotate(180)"/>
            <use href="#bx8" transform="rotate(225)"/>
            <use href="#bx8" transform="rotate(270)"/>
            <use href="#bx8" transform="rotate(315)"/>
            <circle r="22" fill="none" stroke="var(--v7-cinnabar)" stroke-width="1.2" opacity="0.6"/>
            <circle r="8" fill="var(--v7-cinnabar)" opacity="0.7"/>
          </svg>
        </div>
      </header>

      <!-- 主内容 -->
      <main class="main-content">
        <router-view v-slot="{ Component, route: r }">
          <transition name="fade-transform" mode="out-in" @before-enter="resetScroll">
            <keep-alive>
              <component :is="Component" :key="r.path" />
            </keep-alive>
          </transition>
        </router-view>
      </main>
    </div>
  </div>
</template>

<style scoped>
/* ==========================================
   整体框架 — 窄侧边栏
   ========================================== */
.layout-wrapper {
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr);
  height: calc(100vh - 24px);
  margin: 12px;
  position: relative;
  z-index: 2;
  overflow: hidden;
  border-radius: 24px;
  background: var(--v7-surface-card);
  border: 1px solid var(--v7-border-subtle);
  box-shadow:
    0 0 0 1px rgba(201,166,62,.08),
    0 40px 100px -36px rgba(0,0,0,.74),
    var(--v7-glow-gold);
  /* blur 半径从 40px 降到 24px：backdrop-filter 模糊成本随半径超线性增长，
     24px 在半透明暗色卡片上观感几乎一致，却显著降低 GPU 合成开销（issue #4）。 */
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  transform-style: preserve-3d;
  transform: rotateX(var(--tilt-x, 0deg)) rotateY(var(--tilt-y, 0deg));
  transition: transform 0.15s ease-out;
  animation: frameEnter .9s cubic-bezier(.16,1,.3,1) both;
}

/* 金边光效 ::before */
.layout-wrapper::before {
  content: "";
  position: absolute;
  inset: 0;
  z-index: 4;
  pointer-events: none;
  border-radius: 24px;
  padding: 1px;
  background: linear-gradient(135deg,
    transparent 0%,
    var(--v7-gold-mid) 15%,
    transparent 35%,
    var(--v7-gold-bright) 56%,
    transparent 74%,
    var(--v7-gold-deep) 90%
  );
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  opacity: .68;
}

@keyframes frameEnter {
  from { opacity: 0; transform: translateY(24px) scale(.975); }
  to   { opacity: 1; transform: translateY(0) scale(1); }
}

/* ==========================================
   侧边栏 — 墨碑
   ========================================== */
.sidebar {
  position: relative;
  display: flex;
  flex-direction: column;
  min-height: 0;
  padding: 20px 14px;
  background: var(--v7-surface-sidebar);
  border-right: 1px solid var(--v7-border-subtle);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  overflow: hidden;
}

/* 侧边栏光晕氛围 */
.sidebar::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(circle at 20% 8%, rgba(201,166,62,.12), transparent 28%),
    linear-gradient(90deg, rgba(201,166,62,.08), transparent 18%, transparent 82%, rgba(201,166,62,.06));
  opacity: .9;
}

/* 品牌区域 */
.brand-block {
  position: relative;
  z-index: 1;
  display: flex;
  align-items: center;
  gap: 14px;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--v7-border-subtle);
}

.brand-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

/* 导航列表 */
.nav-list {
  position: relative;
  z-index: 1;
  flex: 1;
  padding: 30px 0 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  overflow-y: auto;
}

/* 底部 */
.aside-footer {
  position: relative;
  z-index: 2;
  padding-top: 16px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}

.footer-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.theme-btn {
  transition: transform .3s, box-shadow .3s !important;
}
.theme-btn:hover {
  transform: rotate(30deg);
  box-shadow: 0 0 16px rgba(201,166,62,.24) !important;
}

.version-text {
  font-size: 12px;
  color: var(--v7-text-dim);
  font-weight: 500;
}

.check-btn {
  font-size: 12px;
  color: var(--v7-text-dim) !important;
}

/* ==========================================
   Topbar
   ========================================== */
.main-area {
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  background: transparent;
}

.topbar {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
  height: 56px;
  padding: 0 20px;
  border-bottom: 1px solid var(--v7-border-subtle);
  background: linear-gradient(135deg, rgba(184,149,56,.12), rgba(139,105,20,.06)), var(--v7-surface-card);
  backdrop-filter: blur(12px);
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 14px;
  min-width: 0;
}

.title-stack {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.topbar-title-text {
  font-size: 24px !important;
  line-height: 1.2 !important;
}

.back-btn {
  transition: all .2s;
  flex-shrink: 0;
}
.back-btn:hover {
  background-color: rgba(201,166,62,.1);
  transform: translateX(-2px);
}

/* 顶部八宝纹章 */
.topbar-emblem {
  width: 64px;
  height: 64px;
  flex-shrink: 0;
  animation: slowSpin 40s linear infinite;
}
.emblem-svg {
  width: 100%;
  height: 100%;
}
@keyframes slowSpin {
  to { transform: rotate(360deg); }
}

/* ==========================================
   主内容区
   ========================================== */
.main-content {
  flex: 1;
  min-height: 0;
  padding: 16px 20px 20px;
  overflow-y: auto;
  background: transparent !important;
}

/* ==========================================
   路由过渡动画
   ========================================== */
/* out-in 串行：离开 + 进入时长相加。原各 .32s（合计 ~.64s）切换偏慢；
   离开缩到 .13s、进入 .2s（合计 ~.33s），并减小位移，切换更跟手且保留淡入观感。 */
.fade-transform-enter-active {
  transition: opacity .2s cubic-bezier(.4,0,.2,1), transform .2s cubic-bezier(.4,0,.2,1);
}
.fade-transform-leave-active {
  transition: opacity .13s cubic-bezier(.4,0,.2,1), transform .13s cubic-bezier(.4,0,.2,1);
}
.fade-transform-enter-from { opacity: 0; transform: translateY(8px); }
.fade-transform-leave-to { opacity: 0; transform: translateY(-6px); }

/* ==========================================
   响应式
   ========================================== */
@media (max-width: 1200px) {
  .layout-wrapper {
    grid-template-columns: 220px minmax(0, 1fr);
  }
  .sidebar {
    padding: 20px 14px;
  }
}

@media (max-width: 900px) {
  .layout-wrapper {
    grid-template-columns: 1fr;
  }
  .sidebar {
    display: none;
  }
}

/* 确保所有文字在窄空间下正常显示 */
.topbar-title-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 60vw;
}

.title-stack {
  min-width: 0;
  overflow: hidden;
}

.topbar-left {
  min-width: 0;
  flex: 1;
}

.v7-topbar-kicker {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
