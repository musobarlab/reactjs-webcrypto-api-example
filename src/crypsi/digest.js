import { DIGEST, toHex } from './utils';

async function digest(alg, data) {
    const hash = await crypto.subtle.digest(alg, data);
    return new Uint8Array(hash);
}

export async function sha1DigestHex(data) {
    if (typeof data == 'string') {
        const encoder = new TextEncoder();
        data = encoder.encode(data);
    }

    const buf = await digest(DIGEST['SHA-1'], data);
    return toHex(buf);
}

export async function sha256DigestHex(data) {
    if (typeof data == 'string') {
        const encoder = new TextEncoder();
        data = encoder.encode(data);
    }

    const buf = await digest(DIGEST['SHA-256'], data);
    return toHex(buf);
}

export async function sha384DigestHex(data) {
    if (typeof data == 'string') {
        const encoder = new TextEncoder();
        data = encoder.encode(data);
    }

    const buf = await digest(DIGEST['SHA-384'], data);
    return toHex(buf);
}

export async function sha512DigestHex(data) {
    if (typeof data == 'string') {
        const encoder = new TextEncoder();
        data = encoder.encode(data);
    }

    const buf = await digest(DIGEST['SHA-512'], data);
    return toHex(buf);
}