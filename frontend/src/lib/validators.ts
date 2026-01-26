export function hasInvisibleCharacters(str: string) {
	return /[\u200B-\u200F\uFEFF\u2028\u2029\u180E\u3164\u115F\u1160]/.test(str);
}

export function hasControlCharacters(str: string) {
	return /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str);
}

export function isVisuallyEmpty(str: string) {
	if (!str) return true;
	const stripped = str.replace(/[\s\u200B-\u200F\uFEFF\u2028\u2029\u180E\u3164\u115F\u1160\x00-\x1F\x7F]+/g, '');
	return stripped.length === 0;
}

export function validateText(str: string, label: string) {
	if (!str) return `${label}不能为空`;
	if (isVisuallyEmpty(str)) return `${label}不能为空（包含不可见字符）`;
	if (hasInvisibleCharacters(str)) return `${label}包含非法隐形字符`;
	if (hasControlCharacters(str)) return `${label}包含非法控制字符`;
	return null;
}

