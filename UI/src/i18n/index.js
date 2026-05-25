import { createI18n } from 'vue-i18n'
import zhCN from './locales/zh-CN.js'
import en from './locales/en.js'

// 从 localStorage 读取用户语言偏好，默认中文
const savedLang = localStorage.getItem('language') || 'zh-CN'

const i18n = createI18n({
  legacy: false,           // 使用 Composition API 模式
  locale: savedLang,
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': zhCN,
    'en': en,
  },
})

export default i18n
