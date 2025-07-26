<p align="center">
    <b>@li0ard/gost3413</b><br>
    <b>Cipher modes and padding's according to GOST R 34.13-2015 in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/gost3413">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/gost3413/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/gost3413" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/gost3413"><img src="https://img.shields.io/npm/v/@li0ard/gost3413" /></a>
    <a href="https://jsr.io/@li0ard/gost3413"><img src="https://jsr.io/badges/@li0ard/gost3413" /></a>
    <br>
    <hr>
</p>

> [!WARNING]
> This module contains only wrappers for encryption modes without reference to a specific cipher

## Installation

```bash
# from NPM
npm i @li0ard/gost3413

# from JSR
bunx jsr i @li0ard/gost3413
```

## Supported modes
- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Cipher Feedback (CFB)
- [x] Counter (CTR)
- [x] Output Feedback (OFB)
- [x] MAC (CMAC/OMAC)
- [x] Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM)
- [x] MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM)
- [x] Multilinear Galois Mode (MGM)
- [x] KExp15/KImp15
- [x] Padding method #1 (`Процедура 1`/`Procedure 1`)
- [x] Padding method #2 (`Процедура 2`/`Procedure 2`/`ISO/IEC 7816-4`)
- [x] Padding method #3 (`Процедура 3`/`Procedure 3`)

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [GOST R 34.13-2015 (in Russian)](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf) standard
- Supports Bun, Node.js, Deno, Browsers