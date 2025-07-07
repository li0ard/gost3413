/** Type for cipher function */
export type CipherFunc = (data: Uint8Array) => Uint8Array;
/** Key size */
export const KEYSIZE = 32;
/** ACPKM class */
export interface ACPKMClass {
    /** Encrypting function, that takes block as input */
    encrypt(block: Uint8Array): Uint8Array
}

/** ACPKM class constructor */
export interface ACPKMConstructor {
    new (key: Uint8Array): ACPKMClass
}

/** ACPKM Parameters */
export interface ACPKMParameters {
    /** ACPKM cipher class */
    cipherClass: ACPKMConstructor,
    /** ACPKM section size (N) */
    sectionSize: number
}

export const xor = (a: Uint8Array, b: Uint8Array) => {
    let mlen = Math.min(a.length, b.length)
    let result = new Uint8Array(mlen)
    for(let i = 0; i < mlen; i++) {
        result[i] = a[i] ^ b[i]
    }

    return result.slice()
}


// Code from awesome projects `@noble/curves` and `@noble/hashes`

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}

const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const;
function asciiToBase16(ch: number): number | undefined {
    if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
    if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
    return;
}

export function hexToBytes(hex: string): Uint8Array {
    if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2) throw new Error('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}

const hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
export function bytesToHex(bytes: Uint8Array): string {
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}

export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
    return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}

export function hexToNumber(hex: string): bigint {
    if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
    return hex === '' ? 0n : BigInt('0x' + hex);
}
  
export function bytesToNumberBE(bytes: Uint8Array): bigint {
    return hexToNumber(bytesToHex(bytes));
}