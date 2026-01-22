
import { AwsClient } from 'aws4fetch';

const S3_CONFIG = {
    bucket: 'bucket-1812-2434',
    endpoint: 'https://ny-1s.enzonix.com',
    region: 'us-east-1',
    accessKeyId: '1812kP8lxiNOA5',
    secretAccessKey: 'HoephXxSaQZ47UrBHXo63bNJKM4jyldOebaHmDe6',
    pathPrefix: '/cf-forum' // As requested by user
};

const s3 = new AwsClient({
    accessKeyId: S3_CONFIG.accessKeyId,
    secretAccessKey: S3_CONFIG.secretAccessKey,
    region: S3_CONFIG.region,
    service: 's3',
});

export async function uploadImage(file: File, userId: string | number, postId: string | number = 'general', type: 'post' | 'avatar' = 'post'): Promise<string> {
    const filename = `${Date.now()}-${file.name.replace(/[^a-zA-Z0-9.-]/g, '')}`;
    let key = '';
    
    if (type === 'avatar') {
        key = `${S3_CONFIG.pathPrefix}/usr/${userId}/avatar/${filename}`.replace(/^\/+/, '');
    } else {
        key = `${S3_CONFIG.pathPrefix}/usr/${userId}/post/${postId}/${filename}`.replace(/^\/+/, '');
    }
    
    // Construct the URL manually since aws4fetch fetch is for internal use
    // But we need to PUT the object
    // The endpoint provided is https://ny-1s.enzonix.com
    // For path-style access: https://endpoint/bucket/key
    const url = `${S3_CONFIG.endpoint}/${S3_CONFIG.bucket}/${key}`;

    const res = await s3.fetch(url, {
        method: 'PUT',
        body: file,
        headers: {
            'Content-Type': file.type || 'application/octet-stream',
            // 'x-amz-acl': 'public-read' // Optional, depending on bucket policy
        }
    });

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`S3 Upload Failed: ${res.status} ${err}`);
    }

    // Return the public URL
    // Assuming the bucket is public or we have a public URL structure
    return `${S3_CONFIG.endpoint}/${S3_CONFIG.bucket}/${key}`;
}
