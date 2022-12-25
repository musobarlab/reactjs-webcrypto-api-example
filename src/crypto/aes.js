
import { fromHex, toHex } from './utils';

async function importKeyAES256(rawKey) {
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
    if (key.length < 32) {
        throw new Error(`invalid key length, AES 256 key length should be 32 bytes length`);
    }

    const encoder = new TextEncoder();
    const encoded = encoder.encode(data);
  
    // The iv must never be reused with a given key.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const alg = {
        name: "AES-GCM",
        iv: iv,
    };

    const importedKey = await importKeyAES256(key);

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
    if (key.length < 32) {
        throw new Error(`invalid key length, AES 256 key length should be 32 bytes length`);
    }

    const iv = fromHex(encryptedData.slice(0,24));
    const alg = {
        name: "AES-GCM",
        iv: iv,
    };

    const importedKey = await importKeyAES256(key);

    return await crypto.subtle.decrypt(
        alg, 
        importedKey, 
        fromHex(encryptedData.slice(24, encryptedData.length)),
    );
}
