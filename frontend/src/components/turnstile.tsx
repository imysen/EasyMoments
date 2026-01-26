import * as React from 'react';

type TurnstileGlobal = {
	render: (container: string | HTMLElement, options: { sitekey: string; callback: (token: string) => void }) => unknown;
	reset: (widgetId?: unknown) => void;
};

declare global {
	interface Window {
		turnstile?: TurnstileGlobal;
	}
}

async function ensureTurnstileScriptLoaded(): Promise<void> {
	if (window.turnstile) return;

	await new Promise<void>((resolve, reject) => {
		const existing = document.querySelector<HTMLScriptElement>('script[data-turnstile="1"]');
		if (existing) {
			existing.addEventListener('load', () => resolve());
			existing.addEventListener('error', () => reject(new Error('Turnstile 脚本加载失败')));
			return;
		}

		const script = document.createElement('script');
		script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
		script.async = true;
		script.defer = true;
		script.dataset.turnstile = '1';
		script.addEventListener('load', () => resolve());
		script.addEventListener('error', () => reject(new Error('Turnstile 脚本加载失败')));
		document.head.appendChild(script);
	});
}

export function TurnstileWidget({
	enabled,
	siteKey,
	onToken,
	resetKey
}: {
	enabled: boolean;
	siteKey: string;
	onToken: (token: string) => void;
	resetKey?: string | number;
}) {
	const id = React.useId();
	const containerId = `turnstile-${id.replace(/[:]/g, '')}`;
	const widgetIdRef = React.useRef<unknown>(null);

	React.useEffect(() => {
		if (!enabled) return;

		let cancelled = false;
		(async () => {
			await ensureTurnstileScriptLoaded();
			if (cancelled) return;
			const container = document.getElementById(containerId);
			if (!container || !window.turnstile) return;
			container.innerHTML = '';
			widgetIdRef.current = window.turnstile.render(container, {
				sitekey: siteKey,
				callback: (token) => onToken(token)
			});
		})().catch(() => {});

		return () => {
			cancelled = true;
		};
	}, [enabled, siteKey, containerId, onToken, resetKey]);

	React.useEffect(() => {
		if (!enabled) return;
		if (!window.turnstile) return;
		if (widgetIdRef.current) window.turnstile.reset(widgetIdRef.current);
	}, [enabled, resetKey]);

	if (!enabled) return null;
	return <div id={containerId} className="my-4" />;
}

