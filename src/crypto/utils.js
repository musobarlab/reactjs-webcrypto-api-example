const HEX_STRINGS = "0123456789abcdef";
const MAP_HEX = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6,
    7: 7, 8: 8, 9: 9, a: 10, b: 11, c: 12, d: 13,
    e: 14, f: 15, A: 10, B: 11, C: 12, D: 13,
    E: 14, F: 15
};

export function toHex(bytes) {
    return Array.from(bytes || [])
        .map((b) => HEX_STRINGS[b >> 4] + HEX_STRINGS[b & 15])
        .join("");
}

// Mimics Buffer.from(x, 'hex') logic
// Stops on first non-hex string and returns
// https://github.com/nodejs/node/blob/v14.18.1/src/string_bytes.cc#L246-L261
export function fromHex(hexString) {
    const bytes = new Uint8Array(Math.floor((hexString || "").length / 2));
    let i;
    for (i = 0; i < bytes.length; i++) {
        const a = MAP_HEX[hexString[i * 2]];
        const b = MAP_HEX[hexString[i * 2 + 1]];
        if (a === undefined || b === undefined) {
            break;
        }

        bytes[i] = (a << 4) | b;
    }

    return i === bytes.length ? bytes : bytes.slice(0, i);
}

// Convert a string into an ArrayBuffer
export function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

export function stringToArrayBuffer(data) {
    let buf = decodeURIComponent(encodeURIComponent(data)) // 2 bytes for each char
    let arrayBuf = new Uint8Array(buf.length)
    for (let i=0; i < buf.length; i++) {
        arrayBuf[i] = buf.charCodeAt(i)
    }
    return arrayBuf
}

export function arrayBufferToString(arrayBuffer) {
    let byteArray = new Uint8Array(arrayBuffer)
    let str = ''
    for (let i=0; i<byteArray.byteLength; i++) {
        str += String.fromCharCode(byteArray[i])
    }
    return str
}

export const DIGEST = {
    'SHA-1': 'SHA-1',
    'SHA-256': 'SHA-256',
    'SHA-384': 'SHA-384',
    'SHA-512': 'SHA-512'
};