import { pad1 } from "./index.js";
import { bytesToNumberBE, concatBytes, equalBytes, numberToBytesBE, xor, type CipherFunc, type TArg, type TRet } from "./utils.js"

const _incr = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> =>
    numberToBytesBE(bytesToNumberBE(data) + 1n, (blockSize / 2) | 0);
const incr_r = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> =>
    concatBytes(data.slice(0, ((blockSize / 2) | 0)), _incr(data.slice(((blockSize / 2) | 0)), blockSize));
const incr_l = (data: TArg<Uint8Array>, blockSize: number): TRet<Uint8Array> =>
    concatBytes(_incr(data.slice(0, ((blockSize / 2) | 0)), blockSize), data.slice(((blockSize / 2) | 0)));

// based on go.cypherpunks.su/gogost/mgm
/** Multilinear Galois Mode (MGM) class */
export class MGM {
    tag_size: number;
    encrypter: CipherFunc;
    blockSize: number;
    max_size: bigint;
    r: number;

    /**
     * Prepare nonce
     * 
     * Just clear MSB bit
     * @param nonce Nonce
     */
    static nonce_prepare(nonce: TArg<Uint8Array>): TRet<Uint8Array> {
        let n = nonce.slice();
        n[0] &= 0x7F;
        return n;
    }

    constructor(encrypter: CipherFunc, blockSize: number, tagSize?: number) {
        if(blockSize != 8 && blockSize != 16) throw new Error("Only 64/128-bit block size");

        this.tag_size = tagSize ?? blockSize;
        if(this.tag_size < 4 || this.tag_size > blockSize) throw new Error("Invalid tagSize");

        this.encrypter = encrypter;
        this.blockSize = blockSize;
        // (1n << BigInt((blockSize * 8 / 2) | 0)) - 1n
        this.max_size = (1n << BigInt(blockSize * 4)) - 1n;
        this.r = (blockSize == 8 ? 0x1B : 0x87);
    }

    // Seems to be broken
    private validateNonce(nonce: TArg<Uint8Array>) {
        if(nonce.length != this.blockSize) throw new Error("Invalid nonce length");
        if((nonce[0] & 0x80) > 0) throw new Error("Invalid nonce");
    }

    private validateSizes(plaintext: TArg<Uint8Array>, additional: TArg<Uint8Array>) {
        if(plaintext.length == 0 && additional.length == 0) throw new Error("At least one of plaintext or additional_data required");
        if((plaintext.length + additional.length) > this.max_size) throw new Error("plaintext+additional_data are too big");
    }

    private mul(a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> {
        let x = bytesToNumberBE(a);
        let y = bytesToNumberBE(b);
        let z = 0n;
        let max_bit = 1n << (BigInt(this.blockSize) * 8n - 1n);

        while (y > 0n) {
            if((y & 1n) == 1n) z ^= x;
            if((x & max_bit) > 0n) x = ((x ^ max_bit) << 1n) ^ BigInt(this.r);
            else x <<= 1n;
            y >>= 1n;
        }

        return numberToBytesBE(z, this.blockSize);
    }

    private crypt(icn: TArg<Uint8Array>, data: TArg<Uint8Array>): TRet<Uint8Array> {
        icn[0] &= 0x7F;
        let enc = this.encrypter(icn);
        let res: Uint8Array[] = [];
        while (data.length > 0) {
            res.push(xor(this.encrypter(enc), data));
            enc = incr_r(enc, this.blockSize);
            data = data.slice(this.blockSize);
        }
        return concatBytes(...res);
    }

    private auth(icn: TArg<Uint8Array>, text: TArg<Uint8Array>, ad: TArg<Uint8Array>): TRet<Uint8Array> {
        icn[0] |= 0x80;
        let enc = this.encrypter(icn)
        let _sum = new Uint8Array(this.blockSize);
        let ad_len = ad.length;
        let text_len = text.length;
        while (ad.length > 0) {
            _sum = xor(_sum, this.mul(
                this.encrypter(enc),
                pad1(ad.slice(0, this.blockSize), this.blockSize)
            ));
            enc = incr_l(enc, this.blockSize);
            ad = ad.slice(this.blockSize);
        }

        while (text.length > 0) {
            _sum = xor(_sum, this.mul(
                this.encrypter(enc),
                pad1(text.slice(0, this.blockSize), this.blockSize)
            ));
            enc = incr_l(enc, this.blockSize);
            text = text.slice(this.blockSize);
        }
        const halfbs = (this.blockSize / 2) | 0;
        _sum = xor(_sum, this.mul(this.encrypter(enc), concatBytes(
            numberToBytesBE(ad_len * 8, halfbs),
            numberToBytesBE(text_len * 8, halfbs),
        )));

        return this.encrypter(_sum).slice(0, this.tag_size);
    }

    /**
     * Seal plaintext
     * @param nonce Nonce (blocksized)
     * @param plaintext Data to be encrypted and authenticated
     * @param additional_data Additional data to be authenticated
     */
    public seal(nonce: TArg<Uint8Array>, plaintext: TArg<Uint8Array>, additional_data: TArg<Uint8Array>): TRet<Uint8Array> {
        //this.validateNonce(nonce)
        this.validateSizes(plaintext, additional_data);

        let icn = nonce.slice();
        let ciphertext = this.crypt(icn, plaintext);
        let tag = this.auth(icn, ciphertext, additional_data);
        return concatBytes(ciphertext, tag);
    }

    /**
     * Open ciphertext
     * @param nonce Nonce (blocksized)
     * @param ciphertext Data to be decrypted and authenticated
     * @param additional_data Additional data to be authenticated
     */
    public open(nonce: TArg<Uint8Array>, ciphertext: TArg<Uint8Array>, additional_data: TArg<Uint8Array>): TRet<Uint8Array> {
        //this.validateNonce(nonce)
        this.validateSizes(ciphertext, additional_data);

        let icn = nonce.slice();
        let ct = ciphertext.slice(0, (ciphertext.length - this.tag_size));
        let tag_expected = ciphertext.slice((ciphertext.length - this.tag_size));
        let tag = this.auth(icn, ct, additional_data);
        if(!equalBytes(tag_expected, tag)) throw new Error("Invalid authentication tag");
        return this.crypt(icn, ct);
    }
}