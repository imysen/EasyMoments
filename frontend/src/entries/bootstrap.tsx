import '@/styles/globals.css';
import '@fancyapps/ui/dist/fancybox/fancybox.css';
import { createRoot } from 'react-dom/client';
import * as React from 'react';
import { initTheme } from '@/lib/theme';

export function mount(nodeId: string, element: React.ReactNode) {
	initTheme();
	const el = document.getElementById(nodeId);
	if (!el) throw new Error(`Missing root element #${nodeId}`);
	createRoot(el).render(
		<React.StrictMode>
			{element}
		</React.StrictMode>
	);
}
