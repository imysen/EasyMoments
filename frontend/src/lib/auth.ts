export type User = {
	id: number;
	email: string;
	username: string;
	avatar_url?: string | null;
	role?: 'user' | 'admin';
	totp_enabled?: boolean;
	email_notifications?: boolean;
};

const TOKEN_KEY = 'token';
const USER_KEY = 'user';

export function getToken(): string {
	return localStorage.getItem(TOKEN_KEY) || '';
}

export function setToken(token: string) {
	localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
	localStorage.removeItem(TOKEN_KEY);
}

export function getUser(): User | null {
	try {
		const raw = localStorage.getItem(USER_KEY);
		return raw ? (JSON.parse(raw) as User) : null;
	} catch {
		return null;
	}
}

export function setUser(user: User) {
	localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearUser() {
	localStorage.removeItem(USER_KEY);
}

export function logout() {
	clearToken();
	clearUser();
}

