export type Theme = 'light' | 'dark';

const THEME_KEY = 'theme';

function isTheme(value: unknown): value is Theme {
	return value === 'light' || value === 'dark';
}

export function getTheme(): Theme {
	try {
		const stored = localStorage.getItem(THEME_KEY);
		if (isTheme(stored)) return stored;
	} catch {}
	return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function applyTheme(theme: Theme) {
	document.documentElement.classList.toggle('dark', theme === 'dark');
	document.documentElement.style.colorScheme = theme;
	try {
		localStorage.setItem(THEME_KEY, theme);
	} catch {}
	window.dispatchEvent(new CustomEvent('theme-change', { detail: theme }));
}

export function toggleTheme() {
	applyTheme(getTheme() === 'dark' ? 'light' : 'dark');
}

export function initTheme() {
	const w = window as any;
	if (w.__theme_inited) return;
	w.__theme_inited = true;
	applyTheme(getTheme());
}

