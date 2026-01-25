
import { AwsClient } from 'aws4fetch';

export interface S3Env {
    AWS_ACCESS_KEY_ID: string;
    AWS_SECRET_ACCESS_KEY: string;
    AWS_REGION: string;
    AWS_ENDPOINT: string;
    AWS_BUCKET: string;
    AWS_PATH_PREFIX?: string;
}

function getClient(env: S3Env) {
    return new AwsClient({
        accessKeyId: env.AWS_ACCESS_KEY_ID,
        secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
        region: env.AWS_REGION,
        service: 's3',
    });
}

export async function uploadImage(env: S3Env, file: File, userId: string | number, postId: string | number = 'general', type: 'post' | 'avatar' = 'post'): Promise<string> {
    const s3 = getClient(env);
    const pathPrefix = env.AWS_PATH_PREFIX || '';
    const filename = `${Date.now()}-${file.name.replace(/[^a-zA-Z0-9.-]/g, '')}`;
    let key = '';
    
    if (type === 'avatar') {
        key = `${pathPrefix}/usr/${userId}/avatar/${filename}`.replace(/^\/+/, '');
    } else {
        key = `${pathPrefix}/usr/${userId}/post/${postId}/${filename}`.replace(/^\/+/, '');
    }
    
    const url = `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}/${key}`;

    const res = await s3.fetch(url, {
        method: 'PUT',
        body: file,
        headers: {
            'Content-Type': file.type || 'application/octet-stream',
        }
    });

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`S3 Upload Failed: ${res.status} ${err}`);
    }

    return `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}/${key}`;
}

export async function deleteImage(env: S3Env, imageUrl: string, expectedOwnerId?: string | number): Promise<boolean> {
    const s3 = getClient(env);
    const prefix = `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}/`;
    if (!imageUrl.startsWith(prefix)) return false;

    const key = imageUrl.substring(prefix.length);
    
    if (expectedOwnerId) {
        const userSegment = `/usr/${expectedOwnerId}/`;
        if (!key.includes(userSegment)) {
             console.error(`[Security] Blocked unauthorized image deletion. Key: ${key}, Expected Owner: ${expectedOwnerId}`);
             return false;
        }
    }

    const url = `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}/${key}`;
    const res = await s3.fetch(url, { method: 'DELETE' });
    
    return res.ok;
}

export async function listAllKeys(env: S3Env): Promise<string[]> {
    const s3 = getClient(env);
    const keys: string[] = [];
    let continuationToken: string | undefined = undefined;
    const pathPrefix = env.AWS_PATH_PREFIX || '';
    
    do {
        let url = `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}?list-type=2`;
        if (pathPrefix) {
             const prefix = pathPrefix.replace(/^\/+/, '');
             url += `&prefix=${encodeURIComponent(prefix)}`;
        }

        if (continuationToken) {
            url += `&continuation-token=${encodeURIComponent(continuationToken)}`;
        }
        
        const res = await s3.fetch(url, { method: 'GET' });
        if (!res.ok) throw new Error(`List failed: ${res.status}`);
        
        const text = await res.text();
        
        const matches = text.matchAll(/<Key>(.*?)<\/Key>/g);
        for (const match of matches) {
            keys.push(match[1]);
        }
        
        const nextTokenMatch = text.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/);
        continuationToken = nextTokenMatch ? nextTokenMatch[1] : undefined;
        
    } while (continuationToken);
    
    return keys;
}

export function getPublicUrl(env: S3Env, key: string): string {
    return `${env.AWS_ENDPOINT}/${env.AWS_BUCKET}/${key}`;
}
