import { ref, watch } from 'vue';

const isDark = ref(false);
const THEME_KEY = 'theme';

/**
 * 应用主题到 <html> 元素
 */
function applyTheme(dark) {
    document.documentElement.classList.toggle('dark', dark);
    isDark.value = dark;
}

/**
 * 初始化暗色模式（#92）
 * 优先级：localStorage 用户选择 > 系统偏好
 */
export function useTheme() {
    function initTheme() {
        const saved = localStorage.getItem(THEME_KEY);
        if (saved === 'dark') {
            applyTheme(true);
        } else if (saved === 'light') {
            applyTheme(false);
        } else {
            // 跟随系统
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            applyTheme(prefersDark);
        }

        // 监听系统主题变化（用户未手动设置时生效）
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            if (!localStorage.getItem(THEME_KEY)) {
                applyTheme(e.matches);
            }
        });
    }

    function toggleTheme() {
        const next = !isDark.value;
        applyTheme(next);
        localStorage.setItem(THEME_KEY, next ? 'dark' : 'light');
    }

    function setTheme(dark) {
        applyTheme(dark);
        localStorage.setItem(THEME_KEY, dark ? 'dark' : 'light');
    }

    return { isDark, initTheme, toggleTheme, setTheme };
}
