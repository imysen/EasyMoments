import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { beforeAll, describe, it, expect } from 'vitest';
import worker from '../src';

describe('Worker API smoke tests', () => {
	beforeAll(async () => {
		await env.forum_db.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)').run();
		await env.forum_db.prepare('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, username TEXT, password TEXT)').run();
		await env.forum_db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('turnstile_enabled', '0')").run();
	});

	it('GET /api/config returns expected shape', async () => {
		const request = new Request('http://example.com/api/config', { method: 'GET' });
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		const data = await response.json();
		expect(typeof data.turnstile_enabled).toBe('boolean');
		expect(typeof data.turnstile_site_key).toBe('string');
	});
});
