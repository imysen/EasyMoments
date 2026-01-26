import * as React from 'react';

import type { ForumConfig } from '@/lib/api';

export function useConfig() {
	const [config, setConfig] = React.useState<ForumConfig | null>(null);
	const [error, setError] = React.useState<string>('');

	React.useEffect(() => {
		let cancelled = false;
		(async () => {
			try {
				const res = await fetch('/api/config');
				if (!res.ok) throw new Error('无法加载站点配置');
				const data = (await res.json()) as ForumConfig;
				if (!cancelled) setConfig(data);
			} catch (e: any) {
				if (!cancelled) setError(String(e?.message || e));
			}
		})();
		return () => {
			cancelled = true;
		};
	}, []);

	return { config, error };
}

