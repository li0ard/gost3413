import { type ACPKMConstructor, type ACPKMParameters, bytesToNumberBE, type CipherFunc, concatBytes, KEYSIZE, numberToBytesBE, xor } from "./utils";

export { type ACPKMClass, type ACPKMConstructor, type ACPKMParameters, type CipherFunc, KEYSIZE } from "./utils"

/**
 * Calculate length of padding bytes needed for specific block size.
 * 
 * @param dataLength Length of input data
 * @param blockSize Target block size
 */
export const getPadLength = (dataLength: number, blockSize: number): number => {
    if(dataLength < blockSize) {
        return blockSize - dataLength;
    }
    if(dataLength % blockSize == 0) {
        return 0;
    }
    return blockSize - dataLength % blockSize;
}

/**
 * Procedure 1 (aka `Процедура 1`)
 * 
 * Just fill in with zeros if necessary
 * @param data Input data
 * @param blockSize Target block size
 */
export const pad1 = (data: Uint8Array, blockSize: number): Uint8Array => {
    const padded = new Uint8Array(data.length + getPadLength(data.length, blockSize));
    padded.set(data);
    return padded;
}

/**
 * Prodecure 2 (aka `Процедура 2` aka `ISO/IEC 7816-4`)
 * @param data Input data
 * @param blockSize Target block size
 */
export const pad2 = (data: Uint8Array, blockSize: number): Uint8Array => {
    const padded = new Uint8Array(data.length + 1 + getPadLength(data.length + 1, blockSize));
    padded.set(data, 0);
    padded[data.length] = 0x80;
    return padded;
}

/**
 * Unpadding for Procedure 2
 * @param data Input data
 * @param blockSize Target block size
 */
export const unpad2 = (data: Uint8Array, blockSize: number): Uint8Array => {
    const lastBlock = data.subarray(data.length - blockSize);
    let padIndex = -1;

    for (let i = lastBlock.length - 1; i >= 0; i--) {
        if (lastBlock[i] === 0x80) {
            padIndex = i;
            break;
        }
    }

    if (padIndex === -1) {
        throw new Error("Padding marker (0x80) not found");
    }

    for (let i = padIndex + 1; i < lastBlock.length; i++) {
        if (lastBlock[i] !== 0) {
            throw new Error("Invalid padding: non-zero bytes after 0x80");
        }
    }

    return data.subarray(0, data.length - (blockSize - padIndex));
}

/**
 * Prodecure 3 (aka `Процедура 3`)
 * 
 * If length of data matches block size, do nothing; otherwise, use Procedure 2 (`pad2`)
 * @param data Input data
 * @param blockSize Block size
 */
export const pad3 = (data: Uint8Array, blockSize: number): Uint8Array => {
    if(getPadLength(data.length, blockSize) == 0) return data;
    return pad2(data, blockSize);
}

/**
 * Wrapper for Electronic Codebook (ECB) mode
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 */
export const ecb_encrypt = (encrypter: CipherFunc, blockSize: number, data: Uint8Array): Uint8Array => {
    if (data.length == 0 || data.length % blockSize !== 0) throw new Error("Data not aligned");

    const result = new Uint8Array(data.length);
    let offset = 0;

    for (let i = 0; i < data.length; i += blockSize) {
        const chunk = data.slice(i, i + blockSize)
        const encrypted = encrypter(chunk);
        result.set(encrypted, offset);
        offset += encrypted.length;
    }

    return result.slice();
}

/**
 * Wrapper for Electronic Codebook (ECB) mode
 * @param decrypter Decrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 */
export const ecb_decrypt = (decrypter: CipherFunc, blockSize: number, data: Uint8Array): Uint8Array => {
    if (data.length == 0 || data.length % blockSize !== 0) throw new Error("Data not aligned");

    const result = new Uint8Array(data.length);
    let offset = 0;

    for (let i = 0; i < data.length; i += blockSize) {
        const chunk = data.slice(i, i + blockSize)
        const encrypted = decrypter(chunk);
        result.set(encrypted, offset);
        offset += encrypted.length;
    }

    return result.slice();
}

/**
 * Wrapper for Output Feedback (OFB) mode
 * 
 * For decryption you SHOULD use this function again
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const ofb = (encrypter: CipherFunc, blockSize: number, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    if (iv.length == 0 || iv.length % blockSize !== 0) throw new Error("Invalid IV size");

    let r: Uint8Array[] = [];
    for (let i = 0; i < iv.length; i += blockSize) {
        r.push(iv.subarray(i, i + blockSize));
    }

    const result: Uint8Array[] = [];
    for(let i = 0; i < (data.length + getPadLength(data.length, blockSize)); i += blockSize) {
        r = r.slice(1).concat([encrypter(r[0])]);
        const keystreamBlock = r[r.length - 1];
        const dataBlock = data.subarray(i, i + blockSize);
        result.push(xor(keystreamBlock, dataBlock))
    }

    return concatBytes(...result).slice()
}

/**
 * Wrapper for Cipher Block Chaining (CBC) mode
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const cbc_encrypt = (encrypter: CipherFunc, blockSize: number, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    if (data.length == 0 || data.length % blockSize !== 0) throw new Error("Data not aligned");
    if (iv.length == 0 || iv.length % blockSize !== 0) throw new Error("Invalid IV size");

    let r: Uint8Array[] = [];
    for (let i = 0; i < iv.length; i += blockSize) {
        r.push(iv.subarray(i, i + blockSize));
    }

    const result: Uint8Array[] = [];
    for(let i = 0; i < data.length; i += blockSize) {
        result.push(encrypter(xor(r[0], data.subarray(i, i + blockSize))))
        r = r.slice(1).concat([result[result.length-1]]);
    }

    return concatBytes(...result).slice()
}

/**
 * Wrapper for Cipher Block Chaining (CBC) mode
 * @param decrypter Decrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const cbc_decrypt = (decrypter: CipherFunc, blockSize: number, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    if (data.length == 0 || data.length % blockSize !== 0) throw new Error("Data not aligned");
    if (iv.length == 0 || iv.length % blockSize !== 0) throw new Error("Invalid IV size");

    let r: Uint8Array[] = [];
    for (let i = 0; i < iv.length; i += blockSize) {
        r.push(iv.subarray(i, i + blockSize));
    }

    const result: Uint8Array[] = [];
    for(let i = 0; i < data.length; i += blockSize) {
        let blk = data.subarray(i, i+blockSize)
        result.push(xor(r[0], decrypter(blk)))
        r = r.slice(1).concat([blk])
    }

    return concatBytes(...result).slice()
}

/**
 * Wrapper for Cipher Feedback (CFB) mode
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const cfb_encrypt = (encrypter: CipherFunc, blockSize: number, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    if (iv.length == 0 || iv.length % blockSize !== 0) throw new Error("Invalid IV size");

    let r: Uint8Array[] = [];
    for (let i = 0; i < iv.length; i += blockSize) {
        r.push(iv.subarray(i, i + blockSize));
    }

    const result: Uint8Array[] = [];
    for(let i = 0; i < (data.length + getPadLength(data.length, blockSize)); i += blockSize) {
        result.push(xor(encrypter(r[0]), data.subarray(i, i + blockSize)))
        r = r.slice(1).concat([result[result.length - 1]])
    }

    return concatBytes(...result).slice()
}

/**
 * Wrapper for Cipher Feedback (CFB) mode
 * @param decrypter Decrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const cfb_decrypt = (decrypter: CipherFunc, blockSize: number, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    if (iv.length == 0 || iv.length % blockSize !== 0) throw new Error("Invalid IV size");

    let r: Uint8Array[] = [];
    for (let i = 0; i < iv.length; i += blockSize) {
        r.push(iv.subarray(i, i + blockSize));
    }

    const result: Uint8Array[] = [];
    for(let i = 0; i < (data.length + getPadLength(data.length, blockSize)); i += blockSize) {
        let blk = data.subarray(i, i + blockSize)
        result.push(xor(decrypter(r[0]), blk))
        r = r.slice(1).concat([blk])
    }

    return concatBytes(...result).slice()
}

/**
 * Wrapper for counter (CTR) mode
 * 
 * For decryption you SHOULD use this function again
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector (Half of block size)
 * @param acpkm Optional. Parameters for CTR-ACPKM mode
 */
export const ctr = (encrypter: CipherFunc, blockSize: number, data: Uint8Array, iv: Uint8Array, acpkm?: ACPKMParameters): Uint8Array => {
    const halfBlockSize = (blockSize / 2) | 0;
    if (iv.length !== halfBlockSize) throw new Error("Invalid IV size");

    const ctrMax = 1n << (8n * BigInt(halfBlockSize));
    const maxSize = ctrMax * BigInt(blockSize);
    if (BigInt(data.length) > maxSize) throw new Error("Too big data");
    let acpkmSectionSize = 0;

    if(acpkm) {
        acpkmSectionSize = (acpkm.sectionSize / blockSize) | 0
    }

    const keystreamBlocks: Uint8Array[] = [];
    for (let ctr = 0; ctr < Math.ceil(data.length / blockSize); ctr++) {
        if(acpkm && ctr != 0 && (ctr % acpkmSectionSize) == 0) {
            let cipher = new acpkm.cipherClass(acpkmDerivation(encrypter, blockSize))
            encrypter = cipher.encrypt.bind(cipher)
        }
        keystreamBlocks.push(encrypter(concatBytes(iv, numberToBytesBE(ctr, halfBlockSize))));
    }

    return xor(concatBytes(...keystreamBlocks), data)
}

const Rb64 = 0b11011
const Rb128 = 0b10000111

const macShift = (blockSize: number, data: Uint8Array, xorLsb: number = 0): Uint8Array => {
    const num = (bytesToNumberBE(data) * BigInt(2)) ^ BigInt(xorLsb);
    return numberToBytesBE(num, blockSize).slice(-blockSize);
}

const macKs = (encrypter: (block: Uint8Array) => Uint8Array, blockSize: number): Uint8Array[] => {
    const Rb = blockSize === 16 ? Rb128 : Rb64;
    const l = encrypter(new Uint8Array(blockSize));
    let k1: Uint8Array;
    if ((l[0] & 0x80) !== 0) {
        k1 = macShift(blockSize, l, Rb);
    } else {
        k1 = macShift(blockSize, l);
    }
    let k2: Uint8Array;
    if ((k1[0] & 0x80) !== 0) {
        k2 = macShift(blockSize, k1, Rb);
    } else {
        k2 = macShift(blockSize, k1);
    }
    return [k1, k2];
}

/**
 * Wrapper for MAC (CMAC/OMAC1) mode
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 */
export const mac = (encrypter: CipherFunc, blockSize: number, data: Uint8Array): Uint8Array => {
    const [k1, k2] = macKs(encrypter, blockSize);
    let tailOffset: number;
    if (data.length % blockSize === 0) {
        tailOffset = data.length - blockSize;
    } else {
        tailOffset = data.length - (data.length % blockSize);
    }
    let prev: Uint8Array = new Uint8Array(blockSize);
    for (let i = 0; i < tailOffset; i += blockSize) {
        prev = encrypter(xor(data.subarray(i, i + blockSize), prev));
    }
    const tail = data.subarray(tailOffset);
    const xorWithPrev = xor(pad3(tail, blockSize), prev);
    return encrypter(xor(xorWithPrev, (tail.length === blockSize ? k1 : k2)));
}

/**
 * ACPKM key derivation
 * @param encrypter Encrypting function, that takes block as input
 * @param blockSize Cipher block size
 */
export const acpkmDerivation = (encrypter: CipherFunc, blockSize: number): Uint8Array => {
    let result: Uint8Array[] = []
    for (let d = 0x80; d < (0x80 + blockSize * ((KEYSIZE / blockSize) | 0)); d += blockSize) {
        const block = new Uint8Array(blockSize);
        for (let i = 0; i < blockSize; i++) {
            block[i] = d + i;
        }

        result.push(encrypter(block))
    }

    return concatBytes(...result)
}

/**
 * Wrapper for Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM) mode
 * 
 * For decryption you SHOULD use this function again
 * @param cipherClass Cipher class (see `ACPKMConstructor` and `ACPKMClass`)
 * @param encrypter Encrypting function, that takes block as input
 * @param sectionSize ACPKM section size (N)
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector (Half of block size)
 */
export const ctr_acpkm = (cipherClass: ACPKMConstructor, encrypter: CipherFunc, sectionSize: number, blockSize: number, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    return ctr(encrypter, blockSize, data, iv, {
        cipherClass,
        sectionSize
    })
}

/**
 * ACPKM master key derivation
 * @param cipherClass Cipher class (see `ACPKMConstructor` and `ACPKMClass`)
 * @param encrypter Encrypting function, that takes block as input
 * @param keySectionSize ACPKM key section size (T*)
 * @param blockSize Cipher block size
 * @param keyMaterialLength Length of key material
 */
export const acpkmDerivationMaster = (cipherClass: ACPKMConstructor, encrypter: CipherFunc, keySectionSize: number, blockSize: number, keyMaterialLength: number): Uint8Array => {
    return ctr_acpkm(
        cipherClass,
        encrypter,
        keySectionSize,
        blockSize,
        new Uint8Array(keyMaterialLength).fill(0),
        new Uint8Array((blockSize / 2) | 0).fill(0xFF)
    )
}

/**
 * Wrapper for MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM) mode
 * @param cipherClass Cipher class (see `ACPKMConstructor` and `ACPKMClass`)
 * @param encrypter Encrypting function, that takes block as input
 * @param keySectionSize ACPKM key section size (T*)
 * @param sectionSize ACPKM section size (N)
 * @param blockSize Cipher block size
 * @param data Input data
 */
export const omac_acpkm_master = (cipherClass: ACPKMConstructor, encrypter: CipherFunc, keySectionSize: number, sectionSize: number, blockSize: number, data: Uint8Array): Uint8Array => {
    let tail_offset = 0
    if(data.length % blockSize == 0) {
        tail_offset = data.length - blockSize
    }
    else {
        tail_offset = data.length - (data.length % blockSize)
    }

    let prev: Uint8Array = new Uint8Array(blockSize).fill(0)
    let sections = data.length
    if (data.length % sectionSize != 0) {
        sections += 1
    }
    let keymats = acpkmDerivationMaster(cipherClass, encrypter, keySectionSize, blockSize, (KEYSIZE + blockSize) * sections)
    let k1: Uint8Array = new Uint8Array(sectionSize)
    for(let i = 0; i < tail_offset; i += blockSize) {
        if (i % sectionSize == 0) {
            let keymat = keymats.subarray(0, KEYSIZE + blockSize)
            keymats = keymats.subarray(KEYSIZE + blockSize)
            let key = keymat.subarray(0, KEYSIZE)
            k1 = keymat.subarray(KEYSIZE)
            let cipher = new cipherClass(key)
            encrypter = cipher.encrypt.bind(cipher)
        }
        prev = encrypter(xor(data.subarray(i, i + blockSize), prev))
    }

    let tail = data.subarray(tail_offset)
    if(tail.length == blockSize) {
        let key = keymats.subarray(0, KEYSIZE)
        k1 = keymats.subarray(KEYSIZE)
        let cipher = new cipherClass(key)
        encrypter = cipher.encrypt.bind(cipher)
    }
    let k2 = numberToBytesBE(bytesToNumberBE(k1) << 1n, blockSize)
    if((k1.slice()[0] & 0x80) != 0) {
        k2 = xor(k2, numberToBytesBE(blockSize == 16 ? Rb128 : Rb64, blockSize))
    }
    return encrypter(xor(
        xor(pad3(tail, blockSize), prev),
        (tail.length == blockSize) ? k1 : k2
    ))
}