<template>
  <el-dropdown @command="handleSwitch" trigger="click">
    <span class="lang-switcher">
      <el-icon><Globe /></el-icon>
      {{ currentLabel }}
      <el-icon class="el-icon--right"><ArrowDown /></el-icon>
    </span>
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item command="zh-CN">
          <span :class="{ 'is-active': current === 'zh-CN' }">中文</span>
        </el-dropdown-item>
        <el-dropdown-item command="en">
          <span :class="{ 'is-active': current === 'en' }">English</span>
        </el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Globe, ArrowDown } from '@element-plus/icons-vue'

const { locale } = useI18n()

const current = computed(() => locale.value)

const currentLabel = computed(() => {
  return locale.value === 'en' ? 'English' : '中文'
})

function handleSwitch(lang) {
  locale.value = lang
  localStorage.setItem('language', lang)
  // 刷新页面以应用 Element Plus 语言切换
  window.location.reload()
}
</script>

<style scoped>
.lang-switcher {
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 14px;
  color: var(--el-text-color-regular);
}
.lang-switcher:hover {
  color: var(--el-color-primary);
}
.is-active {
  color: var(--el-color-primary);
  font-weight: bold;
}
</style>
