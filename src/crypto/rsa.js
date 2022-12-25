import { fromHex, toHex, str2ab, DIGEST } from './utils';

async function loadPublicKey(pem, alg) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----\n";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return await crypto.subtle.importKey(
        'spki', 
        binaryDer, 
        {
            name: 'RSA-OAEP',
            hash: alg,
        }, 
        true, 
        ['encrypt']
    );
}

//  format should be PKCS8
async function loadPrivateKey(pem, alg) {
    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----\n";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    console.log(pemContents);
    console.log(alg);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return await window.crypto.subtle.importKey(
        'pkcs8',
        binaryDer,
        {
            name: 'RSA-OAEP',
            hash: alg,
        },
        true,
        ['decrypt']  
    );
}

async function encryptWithOAEP(publicKey, hash, plainData) {
    let key;
    try {
        key = await loadPublicKey(publicKey, hash);
    } catch(e) {
        console.log('encryptWithOAEP error: ', e);
    }
    return await window.crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP',
            hash: hash,
        },
        key,
        plainData,
    );
}

async function decryptWithOAEP(privateKey, hash, encryptedData) {
    const key = await loadPrivateKey(privateKey, hash);
    return await window.crypto.subtle.decrypt(
        {
            name: 'RSA-OAEP',
            hash: hash,
        },
        key,
        encryptedData,
    );
}

// encryption
export function encryptWithOAEPSha1(publicKey, plainData) {
    return encryptWithOAEP(publicKey, DIGEST['SHA-1'], plainData);
}

export function encryptWithOAEPSha256(publicKey, plainData) {
    return encryptWithOAEP(publicKey, DIGEST['SHA-256'], plainData);
}

export function encryptWithOAEPSha384(publicKey, plainData) {
    return encryptWithOAEP(publicKey, DIGEST['SHA-384'], plainData);
}

export function encryptWithOAEPSha512(publicKey, plainData) {
    return encryptWithOAEP(publicKey, DIGEST['SHA-512'], plainData);
}

// decryption
export function decryptWithOAEPSha1(privateKey, encryptedData) {
    return decryptWithOAEP(privateKey, DIGEST['SHA-1'], encryptedData);
}

export function decryptWithOAEPSha256(privateKey, encryptedData) {
    return decryptWithOAEP(privateKey, DIGEST['SHA-256'], encryptedData);
}

export function decryptWithOAEPSha384(privateKey, encryptedData) {
    return decryptWithOAEP(privateKey, DIGEST['SHA-384'], encryptedData);
}

export function decryptWithOAEPSha512(privateKey, encryptedData) {
    return decryptWithOAEP(privateKey, DIGEST['SHA-512'], encryptedData);
}