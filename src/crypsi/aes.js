
import { fromHex, toHex } from './utils';

const AES_128_KEY_SIZE = 16;
const AES_192_KEY_SIZE = 24;
const AES_256_KEY_SIZE = 32;

async function importKeyAES256(rawKey) {
    if (rawKey.length !== AES_256_KEY_SIZE) {
        throw new Error(`invalid key length, AES 256 key length should be ${AES_256_KEY_SIZE} bytes length`);
    }

    const encoder = new TextEncoder();
    return await crypto.subtle.importKey(
        "raw", 
        encoder.encode(rawKey), 
        {
            name: "AES-GCM", 
            length: 256,
        }, 
        true, 
        ['encrypt', 'decrypt'],
    );
}

export async function encryptWithAes256Gcm(key, data) {
    const importedKey = await importKeyAES256(key);

    const encoder = new TextEncoder();
    const encoded = encoder.encode(data);
  
    // The iv must never be reused with a given key.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const alg = {
        name: "AES-GCM",
        iv: iv,
    };

    const cipherData = await crypto.subtle.encrypt(
        alg,
        importedKey,
        encoded,
    );

    const cipherDataBuf = new Uint8Array(cipherData);
    
    let allBuf = new Uint8Array(iv.length+cipherDataBuf.length);
    allBuf.set(iv);
    allBuf.set(cipherDataBuf, iv.length);
    return toHex(allBuf);
}

export async function decryptWithAes256Gcm(key, encryptedData) {
    const importedKey = await importKeyAES256(key);

    const iv = fromHex(encryptedData.slice(0,24));
    const alg = {
        name: "AES-GCM",
        iv: iv,
    };

    return await crypto.subtle.decrypt(
        alg, 
        importedKey, 
        fromHex(encryptedData.slice(24, encryptedData.length)),
    );
}
