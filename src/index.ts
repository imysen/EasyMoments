
import { sendEmail } from './smtp';
import { uploadImage } from './s3';
import * as OTPAuth from 'otpauth';
import { Security, UserPayload } from './security';
import html from '../public/index.html';

// Utility to hash password
async function hashPassword(password: string): Promise<string> {
	const myText = new TextEncoder().encode(password);
	const myDigest = await crypto.subtle.digest(
		{
			name: 'SHA-256',
		},
		myText
	);
	const hashArray = Array.from(new Uint8Array(myDigest));
	const hashHex = hashArray
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	return hashHex;
}

// Utility to generate a random token (simple UUID for now) - DEPRECATED for AUTH, used for verification/reset
function generateToken(): string {
	return crypto.randomUUID();
}

// Utility to check for control characters
function hasControlCharacters(str: string): boolean {
	// eslint-disable-next-line no-control-regex
	return /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
}

const TURNSTILE_SECRET_KEY = '0x4AAAAAACOKzIrdFybmAD67qwlERVgvLMc';

async function verifyTurnstile(token: string, ip: string): Promise<boolean> {
	const formData = new FormData();
	formData.append('secret', TURNSTILE_SECRET_KEY);
	formData.append('response', token);
	formData.append('remoteip', ip);

	const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
	const result = await fetch(url, {
		body: formData,
		method: 'POST',
	});

	const outcome = await result.json() as any;
	return outcome.success;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const method = request.method;
		const security = new Security(env);

		// CORS headers helper
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS, DELETE, PUT',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Nonce',
		};

		// Handle OPTIONS (CORS preflight)
		if (method === 'OPTIONS') {
			return new Response(null, {
				headers: corsHeaders,
			});
		}

		// Helper to return JSON response with CORS
		const jsonResponse = (data: any, status = 200) => {
			return Response.json(data, {
				status,
				headers: corsHeaders,
			});
		};

        // --- AUTH MIDDLEWARE HELPER ---
        const authenticate = async (req: Request): Promise<UserPayload> => {
            const authHeader = req.headers.get('Authorization');
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                throw new Error('Unauthorized');
            }
            const token = authHeader.split(' ')[1];
            const payload = await security.verifyToken(token);
            if (!payload) throw new Error('Invalid Token');
            return payload;
        };

        // --- SECURITY CHECK (Replay + Headers) ---
        // Skip for public GET, Login, Register, Verify, Forgot/Reset Password, Config
        const publicPaths = [
            '/api/config', '/api/login', '/api/register', '/api/verify', 
            '/api/auth/forgot-password', '/api/auth/reset-password', '/api/verify-email-change',
             // Static/Public GETs
            '/api/posts', '/api/categories', '/api/users' 
        ];
        
        // Relax check for public GETs that don't need nonce
        const isPublicGet = method === 'GET' && (
            publicPaths.includes(url.pathname) || 
            url.pathname.match(/^\/api\/posts\/\d+$/) || 
            url.pathname.match(/^\/api\/posts\/\d+\/comments$/)
        );

        // However, user specifically asked for "Replay protection for sensitive operations".
        // We will apply strict checks for mutation methods (POST, PUT, DELETE)
        if (['POST', 'PUT', 'DELETE'].includes(method)) {
             const validation = await security.validateRequest(request);
             if (!validation.valid) {
                 return jsonResponse({ error: validation.error || 'Security check failed' }, 400);
             }
        }

		// GET /api/config
		if (url.pathname === '/api/config' && method === 'GET') {
			try {
				const setting = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first();
				return jsonResponse({
					turnstile_enabled: setting ? setting.value === '1' : false,
					turnstile_site_key: '0x4AAAAAACOKzENkFhyGzGm4'
				});
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/admin/settings
		if (url.pathname === '/api/admin/settings' && method === 'POST') {
			try {
				const body = await request.json() as any;
				const { turnstile_enabled } = body;
				
				await env.forum_db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('turnstile_enabled', ?)").bind(turnstile_enabled ? '1' : '0').run();
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}
		
		// Helper to check Turnstile if enabled
		const checkTurnstile = async (reqBody: any, ip: string) => {
			const setting = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first();
			if (setting && setting.value === '1') {
				const token = reqBody['cf-turnstile-response'];
				if (!token) return false;
				return await verifyTurnstile(token, ip);
			}
			return true;
		};

		// POST /api/upload (Image Upload)
		if (url.pathname === '/api/upload' && method === 'POST') {
			try {
				const user = await authenticate(request);
				
				const formData = await request.formData();
				const file = formData.get('file');
				const userId = user.id.toString(); // Use verified user ID
				const postId = formData.get('post_id') || 'general';
				const type = formData.get('type') || 'post';

				if (!file || !(file instanceof File)) {
					return jsonResponse({ error: 'No file uploaded' }, 400);
				}

				if (!file.type.startsWith('image/')) {
					return jsonResponse({ error: 'Only images are allowed' }, 400);
				}

				// Check file size (500KB = 500 * 1024 bytes)
				const MAX_SIZE = 500 * 1024;
				if (file.size > MAX_SIZE) {
					return jsonResponse({ error: 'File size too large (Max 500KB)' }, 400);
				}

				const imageUrl = await uploadImage(file, userId, postId.toString(), type as 'post' | 'avatar');
				await security.logAudit(user.id, 'UPLOAD_IMAGE', 'image', imageUrl, { type, postId }, request);
				
				return jsonResponse({ success: true, url: imageUrl });
			} catch (e) {
				console.error('Upload error:', e);
				return jsonResponse({ error: String(e) }, 500); // 401/403 will be caught here if auth fails
			}
		}

		// --- AUTH ROUTES ---

		// POST /api/login
		if (url.pathname === '/api/login' && method === 'POST') {
			try {
				const body = await request.json() as any;
				
				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { email, password, totp_code } = body;
				if (!email || !password) {
					return jsonResponse({ error: 'Missing email or password' }, 400);
				}

				const user = await env.forum_db.prepare(
					'SELECT * FROM users WHERE email = ?'
				).bind(email).first();

				if (!user) {
					return jsonResponse({ error: 'Username or Password Error' }, 401);
				}

				if (!user.verified) {
					return jsonResponse({ error: 'Please verify your email first' }, 403);
				}

				const passwordHash = await hashPassword(password);
				if (user.password !== passwordHash) {
					return jsonResponse({ error: 'Username or Password Error' }, 401);
				}

				// TOTP Check
				if (user.totp_enabled) {
					if (!totp_code) {
						return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					}

					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});

					const delta = totp.validate({ token: totp_code, window: 1 });
					if (delta === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				const token = await security.generateToken({
					id: user.id,
					role: user.role || 'user',
					email: user.email
				});

				await security.logAudit(user.id, 'LOGIN', 'user', String(user.id), { email }, request);

				return jsonResponse({
					token,
					user: {
						id: user.id,
						email: user.email,
						username: user.username,
						nickname: user.nickname,
						avatar_url: user.avatar_url,
						role: user.role || 'user',
						totp_enabled: !!user.totp_enabled,
						email_notifications: user.email_notifications === 1
					}
				});
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/user/profile
		if (url.pathname === '/api/user/profile' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { nickname, avatar_url, email_notifications } = body;
				
				const user_id = userPayload.id;

				if (nickname && nickname.length > 20) return jsonResponse({ error: 'Nickname too long (Max 20 chars)' }, 400);

				await env.forum_db.prepare('UPDATE users SET nickname = ?, avatar_url = ?, email_notifications = ? WHERE id = ?')
					.bind(nickname || null, avatar_url || null, email_notifications ? 1 : 0, user_id).run();

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				
				await security.logAudit(userPayload.id, 'UPDATE_PROFILE', 'user', String(user_id), { nickname }, request);

				return jsonResponse({
					success: true,
					user: {
						id: user.id,
						email: user.email,
						username: user.username,
						nickname: user.nickname,
						avatar_url: user.avatar_url,
						role: user.role || 'user',
						totp_enabled: !!user.totp_enabled,
						email_notifications: user.email_notifications === 1
					}
				});
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/user/delete
		if (url.pathname === '/api/user/delete' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { password, totp_code } = body;
				
				if (!password) return jsonResponse({ error: 'Missing credentials' }, 400);

				const user_id = userPayload.id;

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				// Verify Password (Double check for sensitive delete op)
				const passwordHash = await hashPassword(password);
				if (user.password !== passwordHash) {
					return jsonResponse({ error: 'Invalid password' }, 401);
				}

				// Verify TOTP if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				// Delete User and Data
				await env.forum_db.prepare('DELETE FROM likes WHERE user_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE author_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM posts WHERE author_id = ?').bind(user_id).run();
				await env.forum_db.prepare('DELETE FROM users WHERE id = ?').bind(user_id).run();
				
				await security.logAudit(userPayload.id, 'DELETE_ACCOUNT', 'user', String(user_id), {}, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/user/totp/setup
		if (url.pathname === '/api/user/totp/setup' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { user_id } = body; 
				
				if (!user_id) return jsonResponse({ error: 'Missing user_id' }, 400);
				if (userPayload.id !== user_id) return jsonResponse({ error: 'Unauthorized' }, 403);

				const secret = new OTPAuth.Secret({ size: 20 });
				const secretBase32 = secret.base32;

				await env.forum_db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?').bind(secretBase32, user_id).run();

				const user = await env.forum_db.prepare('SELECT email FROM users WHERE id = ?').bind(user_id).first();
				
				await security.logAudit(userPayload.id, 'SETUP_TOTP', 'user', String(user_id), {}, request);

				const totp = new OTPAuth.TOTP({
					issuer: 'CloudflareForum',
					label: user.email,
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: secret
				});

				return jsonResponse({ 
					secret: secretBase32,
					uri: totp.toString() 
				});
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/user/totp/verify
		if (url.pathname === '/api/user/totp/verify' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { user_id, token } = body;

				if (!user_id || !token) return jsonResponse({ error: 'Missing parameters' }, 400);
				if (userPayload.id !== user_id) return jsonResponse({ error: 'Unauthorized' }, 403);

				const user = await env.forum_db.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(user_id).first();
				
				if (!user || !user.totp_secret) return jsonResponse({ error: 'TOTP not setup' }, 400);

				const totp = new OTPAuth.TOTP({
					algorithm: 'SHA1',
					digits: 6,
					period: 30,
					secret: OTPAuth.Secret.fromBase32(user.totp_secret)
				});

				const delta = totp.validate({ token: token, window: 1 });

				if (delta !== null) {
					await env.forum_db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').bind(user_id).run();
					await security.logAudit(userPayload.id, 'ENABLE_TOTP', 'user', String(user_id), {}, request);
					return jsonResponse({ success: true });
				} else {
					return jsonResponse({ error: 'Invalid code' }, 400);
				}
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/auth/forgot-password
		if (url.pathname === '/api/auth/forgot-password' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				const turnstileEnabled = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first();
				
				if (turnstileEnabled && turnstileEnabled.value === '1') {
					const token = body['cf-turnstile-response'];
					if (!token) return jsonResponse({ error: 'Turnstile verification failed (No Token)' }, 403);
					const valid = await verifyTurnstile(token, ip);
					if (!valid) return jsonResponse({ error: 'Turnstile verification failed (Invalid Token)' }, 403);
				}

				const { email } = body;
				if (!email) return jsonResponse({ error: 'Missing email' }, 400);

				const user = await env.forum_db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
				if (!user) return jsonResponse({ success: true }); // Silent fail

				const token = generateToken();
				const expires = Date.now() + 3600000; // 1 hour

				await env.forum_db.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?')
					.bind(token, expires, user.id).run();

				// Base URL logic: Use env var or default to request origin, but override for prod if needed
				const baseUrl = 'https://i.2x.nz'; // Hardcoded as requested
				const resetLink = `${baseUrl}/?reset_token=${token}`;
				
				const emailHtml = `
					<h1>Password Reset Request</h1>
					<p>Click the link below to reset your password:</p>
					<a href="${resetLink}">Reset Password</a>
					<p>If you did not request this, please ignore this email.</p>
					<p>This link expires in 1 hour.</p>
				`;

				ctx.waitUntil(sendEmail(email, 'Password Reset', emailHtml).catch(console.error));
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /auth/reset-password
		if (url.pathname === '/api/auth/reset-password' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				// Explicitly check config first to ensure it is enforced if enabled
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				const turnstileEnabled = await env.forum_db.prepare("SELECT value FROM settings WHERE key = 'turnstile_enabled'").first();
				
				if (turnstileEnabled && turnstileEnabled.value === '1') {
					const token = body['cf-turnstile-response'];
					if (!token) return jsonResponse({ error: 'Turnstile verification failed (No Token)' }, 403);
					const valid = await verifyTurnstile(token, ip);
					if (!valid) return jsonResponse({ error: 'Turnstile verification failed (Invalid Token)' }, 403);
				}

				const { token, new_password, totp_code } = body;
				if (!token || !new_password) return jsonResponse({ error: 'Missing parameters' }, 400);

				if (new_password.length < 8 || new_password.length > 16) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				// Verify tokenuser = await env.forum_db.prepare('SELECT * FROM users WHERE reset_token = ?').bind(token).first();
				
				if (!user) return jsonResponse({ error: 'Invalid token' }, 400);
				if (Date.now() > user.reset_token_expires) return jsonResponse({ error: 'Token expired' }, 400);

				// If user has 2FA, require it
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				const passwordHash = await hashPassword(new_password);
				await env.forum_db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?')
					.bind(passwordHash, user.id).run();

				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/user/change-email
		if (url.pathname === '/api/user/change-email' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { new_email, totp_code } = body; 
				
				if (!new_email) return jsonResponse({ error: 'Missing parameters' }, 400);
				
				const user_id = userPayload.id;

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(user_id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);

				// Verify 2FA if enabled
				if (user.totp_enabled) {
					if (!totp_code) return jsonResponse({ error: 'TOTP_REQUIRED' }, 403);
					const totp = new OTPAuth.TOTP({
						algorithm: 'SHA1',
						digits: 6,
						period: 30,
						secret: OTPAuth.Secret.fromBase32(user.totp_secret)
					});
					if (totp.validate({ token: totp_code, window: 1 }) === null) {
						return jsonResponse({ error: 'Invalid TOTP code' }, 401);
					}
				}

				// Check if email already exists
				const exists = await env.forum_db.prepare('SELECT id FROM users WHERE email = ?').bind(new_email).first();
				if (exists) return jsonResponse({ error: 'Email already in use' }, 400);

				const token = generateToken();
				await env.forum_db.prepare('UPDATE users SET pending_email = ?, email_change_token = ? WHERE id = ?')
					.bind(new_email, token, user.id).run();
				
				await security.logAudit(userPayload.id, 'CHANGE_EMAIL_INIT', 'user', String(user_id), { new_email }, request);

				const baseUrl = 'https://i.2x.nz';
				const verifyLink = `${baseUrl}/api/verify-email-change?token=${token}`;
				const emailHtml = `
					<h1>Confirm Email Change</h1>
					<p>Click the link below to confirm changing your email to ${new_email}:</p>
					<a href="${verifyLink}">Confirm Change</a>
				`;

				ctx.waitUntil(sendEmail(new_email, 'Confirm Email Change', emailHtml).catch(console.error));
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /api/verify-email-change
		if (url.pathname === '/api/verify-email-change' && method === 'GET') {
			const token = url.searchParams.get('token');
			if (!token) return new Response('Missing token', { status: 400 });

			try {
				const user = await env.forum_db.prepare('SELECT * FROM users WHERE email_change_token = ?').bind(token).first();
				if (!user) return new Response('Invalid token', { status: 400 });

				await env.forum_db.prepare('UPDATE users SET email = ?, pending_email = NULL, email_change_token = NULL WHERE id = ?')
					.bind(user.pending_email, user.id).run();

				return Response.redirect(`https://i.2x.nz/?email_changed=true`, 302);
			} catch (e) {
				return new Response('Failed', { status: 500 });
			}
		}

		// POST /api/admin/users/:id/update (Admin direct update)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/update$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { password, email, username } = body;

				if (password && (password.length < 8 || password.length > 16)) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				if (password) {
					const hash = await hashPassword(password);
					await env.forum_db.prepare('UPDATE users SET password = ? WHERE id = ?').bind(hash, id).run();
				}
				if (email) {
					await env.forum_db.prepare('UPDATE users SET email = ? WHERE id = ?').bind(email, id).run();
				}
				if (username) {
					if (username.length > 20) return jsonResponse({ error: 'Username too long (Max 20 chars)' }, 400);
					await env.forum_db.prepare('UPDATE users SET username = ? WHERE id = ?').bind(username, id).run();

					// Notify user about username change
					const user = await env.forum_db.prepare('SELECT email, username FROM users WHERE id = ?').bind(id).first();
					const emailHtml = `
						<h1>Username Changed</h1>
						<p>Your username has been changed to <strong>${username}</strong> by an administrator.</p>
						<p>If you have any questions, please contact support.</p>
					`;
					ctx.waitUntil(sendEmail(user.email, 'Your username has been changed', emailHtml).catch(console.error));
				}
				
				await security.logAudit(userPayload.id, 'ADMIN_UPDATE_USER', 'user', id, { username, email, passwordChanged: !!password }, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /api/categories
		if (url.pathname === '/api/categories' && method === 'GET') {
			try {
				const { results } = await env.forum_db.prepare('SELECT * FROM categories ORDER BY created_at ASC').all();
				return jsonResponse(results);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/admin/categories
		if (url.pathname === '/api/admin/categories' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { name } = body;
				if (!name) return jsonResponse({ error: 'Missing name' }, 400);
				
				const { success } = await env.forum_db.prepare('INSERT INTO categories (name) VALUES (?)').bind(name).run();
				await security.logAudit(userPayload.id, 'CREATE_CATEGORY', 'category', name, {}, request);
				return jsonResponse({ success });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// PUT /api/admin/categories/:id
		if (url.pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'PUT') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { name } = body;
				if (!name) return jsonResponse({ error: 'Missing name' }, 400);
				
				await env.forum_db.prepare('UPDATE categories SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').bind(name, id).run();
				await security.logAudit(userPayload.id, 'UPDATE_CATEGORY', 'category', id, { name }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// DELETE /api/admin/categories/:id
		if (url.pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'DELETE') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				// Check if there are posts in this category
				const count = await env.forum_db.prepare('SELECT COUNT(*) as count FROM posts WHERE category_id = ?').bind(id).first('count');
				if (count > 0) {
					return jsonResponse({ error: 'Cannot delete category with existing posts' }, 400);
				}
				
				await env.forum_db.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
				await security.logAudit(userPayload.id, 'DELETE_CATEGORY', 'category', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// --- ADMIN ROUTES ---

		// GET /api/admin/stats
		if (url.pathname === '/api/admin/stats' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const userCount = await env.forum_db.prepare('SELECT COUNT(*) as count FROM users').first('count');
				const postCount = await env.forum_db.prepare('SELECT COUNT(*) as count FROM posts').first('count');
				const commentCount = await env.forum_db.prepare('SELECT COUNT(*) as count FROM comments').first('count');
				
				return jsonResponse({
					users: userCount,
					posts: postCount,
					comments: commentCount
				});
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /api/admin/users
		if (url.pathname === '/api/admin/users' && method === 'GET') {
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const { results } = await env.forum_db.prepare('SELECT id, email, username, role, verified, created_at FROM users ORDER BY created_at DESC').all();
				return jsonResponse(results);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/admin/users/:id/verify (Manual Verify)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/verify$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const { success } = await env.forum_db.prepare('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?').bind(id).run();
				await security.logAudit(userPayload.id, 'MANUAL_VERIFY_USER', 'user', id, {}, request);
				return jsonResponse({ success });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/admin/users/:id/resend (Resend Verification Email)
		if (url.pathname.match(/^\/api\/admin\/users\/\d+\/resend$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const user = await env.forum_db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
				if (!user) return jsonResponse({ error: 'User not found' }, 404);
				if (user.verified) return jsonResponse({ error: 'User already verified' }, 400);

				// Generate new token if needed, or use existing
				let token = user.verification_token;
				if (!token) {
					token = generateToken();
					await env.forum_db.prepare('UPDATE users SET verification_token = ? WHERE id = ?').bind(token, id).run();
				}

				const baseUrl = 'https://i.2x.nz';
				const verifyLink = `${baseUrl}/api/verify?token=${token}`;
				const emailHtml = `
					<h1>Welcome to the Forum, ${user.username}!</h1>
					<p>Please click the link below to verify your email address:</p>
					<a href="${verifyLink}">Verify Email</a>
					<p>If you did not request this, please ignore this email.</p>
				`;

				ctx.waitUntil(
					sendEmail(user.email, 'Please verify your email', emailHtml)
						.catch(err => console.error('[Background Email Error]', err))
				);
				
				await security.logAudit(userPayload.id, 'RESEND_VERIFY_EMAIL', 'user', id, {}, request);

				return jsonResponse({ success: true, message: 'Verification email sent' });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// DELETE /api/admin/users/:id
		if (url.pathname.startsWith('/api/admin/users/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				// 1. Delete likes and comments ON the user's posts (to avoid orphans)
				await env.forum_db.prepare('DELETE FROM likes WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE post_id IN (SELECT id FROM posts WHERE author_id = ?)').bind(id).run();

				// 2. Delete the user's own activity (likes and comments they made)
				await env.forum_db.prepare('DELETE FROM likes WHERE user_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE author_id = ?').bind(id).run();

				// 3. Delete the user's posts
				await env.forum_db.prepare('DELETE FROM posts WHERE author_id = ?').bind(id).run();

				// 4. Finally, delete the user
				await env.forum_db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_USER', 'user', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// DELETE /api/admin/posts/:id
		if (url.pathname.startsWith('/api/admin/posts/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				await env.forum_db.prepare('DELETE FROM likes WHERE post_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE post_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_POST', 'post', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// DELETE /api/admin/comments/:id
		if (url.pathname.startsWith('/api/admin/comments/') && method === 'DELETE') {
			const id = url.pathname.split('/').pop();
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				// Delete the comment AND its children (orphans prevention)
				await env.forum_db.prepare('DELETE FROM comments WHERE parent_id = ?').bind(id).run();
				await env.forum_db.prepare('DELETE FROM comments WHERE id = ?').bind(id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_DELETE_COMMENT', 'comment', id, {}, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/admin/posts/:id/pin
		if (url.pathname.match(/^\/api\/admin\/posts\/\d+\/pin$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { pinned } = body;
				await env.forum_db.prepare('UPDATE posts SET is_pinned = ? WHERE id = ?').bind(pinned ? 1 : 0, id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_PIN_POST', 'post', id, { pinned }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/admin/posts/:id/move
		if (url.pathname.match(/^\/api\/admin\/posts\/\d+\/move$/) && method === 'POST') {
			const id = url.pathname.split('/')[4];
			try {
				const userPayload = await authenticate(request);
				if (userPayload.role !== 'admin') return jsonResponse({ error: 'Unauthorized' }, 403);

				const body = await request.json() as any;
				const { category_id } = body;
				
				// Validate category exists if provided
				if (category_id) {
					const category = await env.forum_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 404);
				}

				await env.forum_db.prepare('UPDATE posts SET category_id = ? WHERE id = ?').bind(category_id || null, id).run();
				
				await security.logAudit(userPayload.id, 'ADMIN_MOVE_POST', 'post', id, { category_id }, request);
				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// --- END ADMIN ROUTES ---

		// TEST: Email Debug
		if (url.pathname === '/api/test-email' && method === 'POST') {
			try {
				const body = await request.json() as any;
				const { to } = body;
				if (!to) return jsonResponse({ error: 'Missing to address' }, 400);

				console.log('[DEBUG] Starting test email to:', to);
				await sendEmail(to, 'Test Email', '<h1>Hello</h1><p>This is a test.</p>');
				console.log('[DEBUG] Test email sent successfully');
				
				return jsonResponse({ success: true, message: 'Email sent' });
			} catch (e) {
				console.error('[DEBUG] Test email failed:', e);
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// AUTH: Register
		if (url.pathname === '/api/register' && method === 'POST') {
			try {
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { email, username, password } = body;
				if (!email || !username || !password) {
					return jsonResponse({ error: 'Missing email, username or password' }, 400);
				}

				if (username.length > 20) return jsonResponse({ error: 'Username too long (Max 20 chars)' }, 400);
				if (password.length < 8 || password.length > 16) return jsonResponse({ error: 'Password must be 8-16 characters' }, 400);

				const passwordHash = await hashPassword(password);
				const verificationToken = generateToken();

				const { success } = await env.forum_db.prepare(
					'INSERT INTO users (email, username, password, role, verified, verification_token) VALUES (?, ?, ?, "user", 0, ?)'
				).bind(email, username, passwordHash, verificationToken).run();

				if (success) {
					// Send verification email asynchronously
					const baseUrl = 'https://i.2x.nz';
					const verifyLink = `${baseUrl}/api/verify?token=${verificationToken}`;
					
					const emailHtml = `
						<h1>Welcome to the Forum, ${username}!</h1>
						<p>Please click the link below to verify your email address:</p>
						<a href="${verifyLink}">Verify Email</a>
						<p>If you did not request this, please ignore this email.</p>
					`;
					
					// IMPORTANT: Use waitUntil to ensure background task completes, but catch errors to log them
					ctx.waitUntil(
						sendEmail(email, 'Please verify your email', emailHtml)
							.catch(err => console.error('[Background Email Error]', err))
					);
				}

				return jsonResponse({ success, message: 'User registered successfully. Please check your email to verify your account.' }, 201);
			} catch (e: any) {
				if (e.message && e.message.includes('UNIQUE constraint failed')) {
					return jsonResponse({ error: 'Email already exists' }, 409);
				}
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// AUTH: Verify Email
		if (url.pathname === '/api/verify' && method === 'GET') {
			const token = url.searchParams.get('token');
			if (!token) {
				return new Response('Missing token', { status: 400 });
			}

			try {
				const { success } = await env.forum_db.prepare(
					'UPDATE users SET verified = 1, verification_token = NULL WHERE verification_token = ?'
				).bind(token).run();

				if (success) {
					// Redirect to home page with verified param
					return Response.redirect(`https://i.2x.nz/?verified=true`, 302);
				} else {
					return new Response('Invalid or expired token', { status: 400 });
				}
			} catch (e) {
				return new Response('Verification failed', { status: 500 });
			}
		}

		// GET /users
		if (url.pathname === '/api/users' && method === 'GET') {
			try {
				const { results } = await env.forum_db.prepare(
					'SELECT id, email, username, created_at FROM users'
				).all();
				return jsonResponse(results);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /api/user/likes (Get all post IDs liked by user)
		if (url.pathname === '/api/user/likes' && method === 'GET') {
			const userId = url.searchParams.get('user_id');
			if (!userId) return jsonResponse({ error: 'Missing user_id' }, 400);
			try {
				const { results } = await env.forum_db.prepare('SELECT post_id FROM likes WHERE user_id = ?').bind(userId).all();
				return jsonResponse(results.map((r: any) => r.post_id));
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /posts
		if (url.pathname === '/api/posts' && method === 'GET') {
			try {
				const limit = parseInt(url.searchParams.get('limit') || '20');
				const offset = parseInt(url.searchParams.get('offset') || '0');
				const categoryId = url.searchParams.get('category_id');
				
				let query = `SELECT 
                        posts.*, 
                        users.username as author_name, 
                        users.nickname as author_nickname, 
                        users.avatar_url as author_avatar,
                        users.role as author_role,
                        categories.name as category_name,
                        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
                        (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
                     FROM posts 
                     JOIN users ON posts.author_id = users.id 
                     LEFT JOIN categories ON posts.category_id = categories.id`;
                
                const params: any[] = [];
                if (categoryId) {
                    query += ` WHERE posts.category_id = ?`;
                    params.push(categoryId);
                }

                query += ` ORDER BY is_pinned DESC, posts.created_at DESC LIMIT ? OFFSET ?`;
                params.push(limit, offset);
				
				const { results } = await env.forum_db.prepare(query).bind(...params).all();
				return jsonResponse(results);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /api/posts/:id
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			try {
				const post = await env.forum_db.prepare(
					`SELECT 
                        posts.*, 
                        users.username as author_name, 
                        users.nickname as author_nickname, 
                        users.avatar_url as author_avatar,
                        users.role as author_role,
                        categories.name as category_name,
                        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) as like_count,
                        (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id) as comment_count
                     FROM posts 
                     JOIN users ON posts.author_id = users.id 
                     LEFT JOIN categories ON posts.category_id = categories.id
                     WHERE posts.id = ?`
				).bind(postId).first();
				
				if (!post) return jsonResponse({ error: 'Post not found' }, 404);
				
				// Check like status if user_id provided
				const userId = url.searchParams.get('user_id');
				if (userId) {
					const like = await env.forum_db.prepare('SELECT id FROM likes WHERE post_id = ? AND user_id = ?').bind(postId, userId).first();
					(post as any).liked = !!like;
				}

				return jsonResponse(post);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// PUT /api/posts/:id
		if (url.pathname.match(/^\/api\/posts\/\d+$/) && method === 'PUT') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;
				const { title, content, category_id } = body; // user_id not needed from body

				if (!title || !content) {
					return jsonResponse({ error: 'Missing parameters' }, 400);
				}

				// Check ownership or admin
				const post = await env.forum_db.prepare('SELECT author_id FROM posts WHERE id = ?').bind(postId).first();
				if (!post) return jsonResponse({ error: 'Post not found' }, 404);

				// Use userPayload for RBAC
				if (post.author_id !== userPayload.id && userPayload.role !== 'admin') {
					return jsonResponse({ error: 'Unauthorized' }, 403);
				}

				// Validate Lengths
				if (title.length > 30) return jsonResponse({ error: 'Title too long (Max 30 chars)' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Content too long (Max 3000 chars)' }, 400);
				if (hasControlCharacters(title) || hasControlCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid control characters' }, 400);

				// Validate Category
				if (category_id) {
					const category = await env.forum_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 400);
				}

				await env.forum_db.prepare(
					'UPDATE posts SET title = ?, content = ?, category_id = ? WHERE id = ?'
				).bind(title, content, category_id || null, postId).run();
				
				await security.logAudit(userPayload.id, 'UPDATE_POST', 'post', postId, { title_length: title.length }, request);

				return jsonResponse({ success: true });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// GET /api/posts/:id/comments
		if (url.pathname.match(/^\/api\/posts\/\d+\/comments$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			try {
				const { results } = await env.forum_db.prepare(
					`SELECT comments.*, users.username, users.nickname, users.avatar_url, users.role 
                     FROM comments 
                     JOIN users ON comments.author_id = users.id 
                     WHERE post_id = ? 
                     ORDER BY created_at ASC`
				).bind(postId).all();
				return jsonResponse(results);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/posts/:id/comments
		if (url.pathname.match(/^\/api\/posts\/\d+\/comments$/) && method === 'POST') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				let { content, parent_id } = body;
				// user_id comes from token now
				
				if (!content) return jsonResponse({ error: 'Missing parameters' }, 400);
				if (!content.trim()) return jsonResponse({ error: 'Comment cannot be empty' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Comment too long (Max 3000 chars)' }, 400);
				if (hasControlCharacters(content)) return jsonResponse({ error: 'Comment contains invalid control characters' }, 400);
				
				// "Reply to Reply" Logic: Flatten to Level 2 with @Mention
				let originalParentAuthorId = null; // Track who was *originally* replied to for notifications

				if (parent_id) {
					const parent = await env.forum_db.prepare('SELECT parent_id, author_id FROM comments WHERE id = ?').bind(parent_id).first();
					
					if (parent) {
						if (parent.parent_id !== null) {
							// Level 3 attempt detected.
							// 1. Fetch nickname of the user being replied to
							const targetUser = await env.forum_db.prepare('SELECT username, nickname FROM users WHERE id = ?').bind(parent.author_id).first();
							const targetName = targetUser.nickname || targetUser.username;

							// 2. Rewrite content and parent_id
							content = `@${targetName} ${content}`;
							parent_id = parent.parent_id; // Move up to share the same Level 1 parent
							originalParentAuthorId = parent.author_id; // We still want to notify the specific user we @mentioned
						} else {
							// Normal Level 2 reply
							originalParentAuthorId = parent.author_id;
						}
					}
				}

				const { success } = await env.forum_db.prepare(
					'INSERT INTO comments (post_id, author_id, content, parent_id) VALUES (?, ?, ?, ?)'
				).bind(postId, userPayload.id, content, parent_id || null).run();
				
				await security.logAudit(userPayload.id, 'CREATE_COMMENT', 'comment', 'new', { postId, parent_id }, request);

				// Email Notification Logic
				if (success) {
					// 1. Notify Post Author
					const post = await env.forum_db.prepare(
						'SELECT posts.title, users.id as author_id, users.email, users.email_notifications, users.username FROM posts JOIN users ON posts.author_id = users.id WHERE posts.id = ?'
					).bind(postId).first();

					// Fetch commenter name
					const commenter = await env.forum_db.prepare('SELECT username, nickname FROM users WHERE id = ?').bind(userPayload.id).first();
					const commenterName = commenter.nickname || commenter.username;
					const postUrl = `https://i.2x.nz/posts/${postId}`;

					// Notify Post Author (if not self)
					if (post && post.author_id !== userPayload.id && post.email_notifications === 1) {
						const emailHtml = `
							<h1>New Comment on your post</h1>
							<p><strong>${commenterName}</strong> commented on your post "<strong>${post.title}</strong>":</p>
							<blockquote>${content}</blockquote>
							<p><a href="${postUrl}">View Comment</a></p>
							<p style="font-size:0.8em;color:#666;">You received this email because you are subscribed to notifications.</p>
						`;
						ctx.waitUntil(sendEmail(post.email, `New comment on: ${post.title}`, emailHtml).catch(console.error));
					}

					// 2. Notify Parent Comment Author (if replying to a comment)
					if (parent_id || originalParentAuthorId) {
						// Determine who to notify:
						// If originalParentAuthorId is set, it means we flattened a Level 3 reply and should notify that specific user.
						// Otherwise, notify the direct parent (Level 1).
						
						const notifyUserId = originalParentAuthorId || (
							parent_id ? (await env.forum_db.prepare('SELECT author_id FROM comments WHERE id = ?').bind(parent_id).first())?.author_id : null
						);

						if (notifyUserId) {
							const parentCommentUser = await env.forum_db.prepare(
								'SELECT email, email_notifications, username, nickname FROM users WHERE id = ?'
							).bind(notifyUserId).first();

							if (parentCommentUser && notifyUserId !== userPayload.id && parentCommentUser.email_notifications === 1) {
								// Avoid double notification if parent author is also post author (already handled above)
								if (notifyUserId !== post.author_id) {
									const replyHtml = `
										<h1>New Reply to your comment</h1>
										<p><strong>${commenterName}</strong> replied to your comment on "<strong>${post.title}</strong>":</p>
										<blockquote>${content}</blockquote>
										<p><a href="${postUrl}">View Reply</a></p>
										<p style="font-size:0.8em;color:#666;">You received this email because you are subscribed to notifications.</p>
									`;
									ctx.waitUntil(sendEmail(parentCommentUser.email, `New reply to your comment`, replyHtml).catch(console.error));
								}
							}
						}
					}
				}

				return jsonResponse({ success }, 201);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /api/posts/:id/like
		if (url.pathname.match(/^\/api\/posts\/\d+\/like$/) && method === 'POST') {
			const postId = url.pathname.split('/')[3];
			try {
				const userPayload = await authenticate(request);
				const userId = userPayload.id;

				// Toggle like
				const existing = await env.forum_db.prepare(
					'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
				).bind(postId, userId).first();

				if (existing) {
					await env.forum_db.prepare('DELETE FROM likes WHERE id = ?').bind(existing.id).run();
					return jsonResponse({ liked: false });
				} else {
					await env.forum_db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').bind(postId, userId).run();
					return jsonResponse({ liked: true });
				}
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}
		
		// GET /api/posts/:id/like-status
		if (url.pathname.match(/^\/api\/posts\/\d+\/like-status$/) && method === 'GET') {
			const postId = url.pathname.split('/')[3];
			const userId = url.searchParams.get('user_id');
			if (!userId) return jsonResponse({ liked: false });
			
			try {
				const existing = await env.forum_db.prepare(
					'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
				).bind(postId, userId).first();
				return jsonResponse({ liked: !!existing });
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// POST /posts (Protected - in real app check token)
		if (url.pathname === '/api/posts' && method === 'POST') {
			try {
				const userPayload = await authenticate(request);
				const body = await request.json() as any;

				// Turnstile Check
				const ip = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
				if (!(await checkTurnstile(body, ip))) {
					return jsonResponse({ error: 'Turnstile verification failed' }, 403);
				}

				const { title, content, category_id } = body;
				
				if (!title || !content) {
					return jsonResponse({ error: 'Missing title or content' }, 400);
				}
				
				if (!title.trim() || !content.trim()) return jsonResponse({ error: 'Title or content cannot be empty' }, 400);
				
				// Validate Lengths
				if (title.length > 30) return jsonResponse({ error: 'Title too long (Max 30 chars)' }, 400);
				if (content.length > 3000) return jsonResponse({ error: 'Content too long (Max 3000 chars)' }, 400);

				if (hasControlCharacters(title) || hasControlCharacters(content)) return jsonResponse({ error: 'Title or content contains invalid control characters' }, 400);

				// Validate Category
				if (category_id) {
					const category = await env.forum_db.prepare('SELECT id FROM categories WHERE id = ?').bind(category_id).first();
					if (!category) return jsonResponse({ error: 'Category not found' }, 400);
				}

				const { success } = await env.forum_db.prepare(
					'INSERT INTO posts (author_id, title, content, category_id) VALUES (?, ?, ?, ?)'
				).bind(userPayload.id, title, content, category_id || null).run();
				
				await security.logAudit(userPayload.id, 'CREATE_POST', 'post', 'new', { title_length: title.length }, request);

				return jsonResponse({ success }, 201);
			} catch (e) {
				return jsonResponse({ error: String(e) }, 500);
			}
		}

		// SPA Fallback
		if (method === 'GET' && !url.pathname.startsWith('/api')) {
			return new Response(html, {
				headers: { 'Content-Type': 'text/html' }
			});
		}

		return new Response('Not Found', { status: 404 });
	},
} satisfies ExportedHandler<Env>;
