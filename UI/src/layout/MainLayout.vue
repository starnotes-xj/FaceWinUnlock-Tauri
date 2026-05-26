<script setup lang="ts">
    import { ref } from 'vue';
    import { RouterView } from 'vue-router';
    import {
        Avatar,
        Odometer,
        User,
        Setting,
        Tools,
        Sunny,
        Moon
    } from '@element-plus/icons-vue'
    import { useTheme } from '../hook/useTheme';

    const version = ref(localStorage.getItem("version") || 'unknown');
    const { isDark, toggleTheme } = useTheme();

    /** 路由切换时重置 el-main 滚动位置，防止从长页面切回短页面后内容不可见 */
    function resetScroll() {
        const el = document.querySelector('.main-content');
        if (el) el.scrollTop = 0;
    }
</script>

<template>
     <el-container class="layout-container">
        <el-aside width="240px" class="aside-menu">
            <div class="logo-area">
                <el-icon size="28" color="#409EFF">
                    <Avatar />
                </el-icon>
                <span class="logo-text">Tauri 面容解锁</span>
            </div>

            <el-menu :default-active="$route.path" router class="custom-menu">
                <el-menu-item index="/">
                    <el-icon>
                        <Odometer />
                    </el-icon>
                    <span>仪表盘</span>
                </el-menu-item>

                <el-menu-item index="/faces">
                    <el-icon>
                        <User />
                    </el-icon>
                    <span>面容管理</span>
                </el-menu-item>

                <el-menu-item index="/options">
                    <el-icon>
                        <Setting />
                    </el-icon>
                    <span>首选项</span>
                </el-menu-item>

                <el-menu-item index="/logs">
                    <el-icon>
                        <Tickets />
                    </el-icon>
                    <span>日志</span>
                </el-menu-item>
            </el-menu>

            <div class="aside-footer">
                <!-- 主题切换（#92 暗色模式） -->
                <el-button
                    :icon="isDark ? Sunny : Moon"
                    circle
                    size="small"
                    @click="toggleTheme"
                    class="theme-toggle-btn"
                    :title="isDark ? '切换亮色模式' : '切换暗色模式'"
                />
                <div class="version-info">
                    <span class="version-label">版本</span>
                    <span class="version-number">v {{ version }}</span>
                </div>
                <el-tag size="small" type="success" effect="plain">系统服务已就绪</el-tag>
            </div>
        </el-aside>

        <el-container>
            <el-header class="global-header" height="50px">
                <div class="left-section">
                    <el-button
                        v-if="$route.path !== '/'"
                        icon="ArrowLeft"
                        circle
                        size="small"
                        @click="$router.back()"
                        class="back-btn"
                    />
                    <span class="page-title">{{ $route.meta.title || '面容识别系统' }}</span>
                </div>
                <div class="right-section"></div>
            </el-header>
            <el-main class="main-content">
                <router-view v-slot="{ Component }">
                    <transition name="fade-transform" mode="out-in"
                        @before-enter="resetScroll">
                        <component :is="Component" :key="$route.path" />
                    </transition>
                </router-view>
            </el-main>
        </el-container>
    </el-container>
</template>

<style scoped>
    .layout-container {
        display: flex;
        height: 100vh;
        background-color: var(--el-bg-color-page, #f9f9f9);
    }

    /* 侧边栏样式 */
    .aside-menu {
        background-color: var(--el-bg-color, #ffffff);
        border-right: 1px solid var(--el-border-color-light, #e6e6e6);
        display: flex;
        flex-direction: column;
    }

    .logo-area {
        height: 80px;
        display: flex;
        align-items: center;
        padding: 0 25px;
        gap: 12px;
    }

    .logo-text {
        font-size: 18px;
        font-weight: 600;
        color: var(--el-text-color-primary, #303133);
    }

    .custom-menu {
        border-right: none;
        flex: 1;
    }

    /* 底部状态 */
    .aside-footer {
        padding: 15px 20px;
        border-top: 1px solid var(--el-border-color-lighter, #f0f0f0);
        text-align: center;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 10px;
    }

    .theme-toggle-btn {
        transition: transform 0.3s ease;
    }
    .theme-toggle-btn:hover {
        transform: rotate(30deg);
    }

    .version-info {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 4px;
        font-size: 12px;
        color: var(--el-text-color-placeholder, #909399);
    }

    .version-label {
        color: var(--el-text-color-disabled, #c0c4cc);
    }

    .version-number {
        font-weight: 500;
        color: var(--el-text-color-regular, #606266);
    }

    .status-tag {
        margin: 0;
    }

    /* 主内容区 */
    .main-content {
        padding: 30px;
        overflow-y: auto;
    }

    .global-header {
        background-color: var(--el-bg-color, #fff);
        border-bottom: 1px solid var(--el-border-color-light, #e6e6e6);
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 20px;
    }

    .left-section {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .back-btn {
        transition: all 0.2s;
    }

    .back-btn:hover {
        background-color: var(--el-color-primary-light-9, #ecf5ff);
        transform: translateX(-2px);
    }

    .page-title {
        font-size: 14px;
        font-weight: 600;
        color: var(--el-text-color-regular, #606266);
    }

    /* 页面切换动画 — 只过渡 opacity + transform，
       不能用 all（会把子页面的 height/flex 也过渡，导致仪表盘切回时白屏） */
    .fade-transform-enter-active,
    .fade-transform-leave-active {
        transition: opacity 0.3s cubic-bezier(0.4, 0, 0.2, 1),
                    transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .fade-transform-enter-from {
        opacity: 0;
        transform: translateY(10px);
    }

    .fade-transform-leave-to {
        opacity: 0;
        transform: translateY(-10px);
    }
</style>
