import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import worker from '../src';

describe('Category Management', () => {
    // Helper to run fetch against the worker
    async function runFetch(url: string, method: string = 'GET', body?: any) {
        const request = new Request(`http://example.com${url}`, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : undefined
        });
        const ctx = createExecutionContext();
        const response = await worker.fetch(request, env, ctx);
        await waitOnExecutionContext(ctx);
        return response;
    }

    // Initialize DB schema for tests
    beforeAll(async () => {
        // Create tables
        await env.forum_db.exec(`
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                verified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category_id INTEGER,
                is_pinned INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            );
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        `);
    });

    it('should allow admin to create a category', async () => {
        const res = await runFetch('/api/admin/categories', 'POST', { name: 'Tech' });
        expect(res.status).toBe(200);
        const data = await res.json();
        expect(data.success).toBe(true);
    });

    it('should list categories', async () => {
        const res = await runFetch('/api/categories');
        expect(res.status).toBe(200);
        const categories = await res.json();
        expect(Array.isArray(categories)).toBe(true);
        expect(categories.length).toBeGreaterThan(0);
        expect(categories[0].name).toBe('Tech');
    });

    it('should allow admin to update a category', async () => {
        // Get ID first
        const listRes = await runFetch('/api/categories');
        const categories = await listRes.json();
        const id = categories[0].id;

        const res = await runFetch(`/api/admin/categories/${id}`, 'PUT', { name: 'Technology' });
        expect(res.status).toBe(200);
        
        const listRes2 = await runFetch('/api/categories');
        const categories2 = await listRes2.json();
        expect(categories2[0].name).toBe('Technology');
    });

    it('should allow creating a post with a category', async () => {
        // Create user first
        await env.forum_db.prepare("INSERT INTO users (email, username, password, role) VALUES ('test@example.com', 'tester', 'hash', 'user')").run();
        const user = await env.forum_db.prepare("SELECT * FROM users WHERE email = 'test@example.com'").first();

        // Get Category ID
        const listRes = await runFetch('/api/categories');
        const categories = await listRes.json();
        const catId = categories[0].id;

        const res = await runFetch('/api/posts', 'POST', {
            author_id: user.id,
            title: 'Test Post',
            content: 'Content',
            category_id: catId
        });
        expect(res.status).toBe(201);
    });

    it('should filter posts by category', async () => {
        // Get Category ID
        const listRes = await runFetch('/api/categories');
        const categories = await listRes.json();
        const catId = categories[0].id;

        const res = await runFetch(`/api/posts?category_id=${catId}`);
        expect(res.status).toBe(200);
        const posts = await res.json();
        expect(posts.length).toBe(1);
        expect(posts[0].category_name).toBe('Technology');
    });
    
    it('should allow admin to delete a category (if empty)', async () => {
        // Create empty category
        await runFetch('/api/admin/categories', 'POST', { name: 'Empty' });
        const listRes = await runFetch('/api/categories');
        const categories = await listRes.json();
        const emptyCat = categories.find(c => c.name === 'Empty');

        const res = await runFetch(`/api/admin/categories/${emptyCat.id}`, 'DELETE');
        expect(res.status).toBe(200);
        expect((await res.json()).success).toBe(true);
    });
});
