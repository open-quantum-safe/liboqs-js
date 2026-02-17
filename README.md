# @oqs/liboqs-js

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-22+-green.svg)](https://nodejs.org/)

A JavaScript/TypeScript wrapper for [LibOQS](https://github.com/open-quantum-safe/liboqs), providing access to post-quantum cryptographic algorithms for key encapsulation mechanisms (KEM) and digital signatures.

## Overview

This library provides WebAssembly bindings to LibOQS, part of the [Open Quantum Safe](https://openquantumsafe.org/) project. It includes:

- Individual WASM modules per algorithm for optimal bundle sizes
- TypeScript definitions for complete type safety
- Support for Node.js and browser environments
- SIMD-optimized builds for maximum performance
- Tree-shakable ES module exports to minimize bundle size
- Automatic memory management and secure cleanup

## Status

### ⚠️ Important Notice

**This library is meant for research, prototyping, and experimentation.** While the underlying LibOQS library is well-maintained by the Open Quantum Safe project, both projects carry important caveats:

- Most post-quantum algorithms have not received the same level of scrutiny as traditional cryptography
- Algorithm support may change rapidly as research advances
- Some algorithms may prove insecure against classical or quantum computers
- This library has not received a formal security audit

**If you must use post-quantum cryptography in production environments**, use **hybrid approaches** that combine post-quantum algorithms with traditional algorithms (e.g., ML-KEM with X25519, ML-DSA with Ed25519). This provides defense-in-depth during the transition period.

For production deployments, follow guidance from NIST's [Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography) project.

### NIST Standardized Algorithms

The algorithms implementing NIST FIPS standards are:
- **ML-KEM** (FIPS 203, formerly Kyber): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA** (FIPS 204, formerly Dilithium): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (FIPS 205, formerly SPHINCS+): 12 variants (SHA2 and SHAKE, 128/192/256-bit security, f/s modes)

These algorithm names are stable and will be maintained. If NIST updates implementation details, this library will track those changes as closely as possible.

### Available Algorithms

The library provides JavaScript wrappers for **103 algorithms** including experimental and alternative post-quantum schemes:

<details>
<summary>Key Encapsulation Mechanisms (38 algorithms)</summary>

- **Kyber** (legacy, use ML-KEM): `Kyber512`, `Kyber768`, `Kyber1024`
- **Classic McEliece**: 10 variants (`Classic-McEliece-348864` through `Classic-McEliece-8192128f`)
- **FrodoKEM**: 6 salted variants (AES and SHAKE, 640/976/1344-bit)
- **eFrodoKEM**: 6 ephemeral variants (AES and SHAKE, 640/976/1344-bit)
- **HQC**: `HQC-128`, `HQC-192`, `HQC-256`
- **NTRU**: 6 variants (HPS and HRSS families)
- **NTRU Prime**: `sntrup761`

**Note**: BIKE family is not supported due to WASM incompatibility (requires platform-specific optimizations).

</details>

<details>
<summary>Digital Signatures (65 algorithms)</summary>

- **Falcon**: `Falcon-512`, `Falcon-1024`, `Falcon-padded-512`, `Falcon-padded-1024`
- **SLH-DSA** (FIPS 205): 12 variants (SHA2 and SHAKE, 128/192/256-bit security, f/s modes)
- **CROSS**: 18 variants (RSDP and RSDPG parameter sets with balanced/fast/small tradeoffs)
- **MAYO**: `MAYO-1`, `MAYO-2`, `MAYO-3`, `MAYO-5`
- **SNOVA**: 12 variants (various parameter sets)
- **UOV**: 12 variants (Ip, Is, III, V with different optimization levels)

</details>

See `algorithms.json` for the complete algorithm registry, or [the algorithms section](#available-algorithms-1). All 103 algorithms have WASM modules, JavaScript wrappers, TypeScript definitions, and test coverage.

## Installation

This package works with all major JavaScript package managers:

```bash
# bun (recommended - fastest)
bun add @oqs/liboqs-js

# npm
npm install @oqs/liboqs-js

# pnpm
pnpm add @oqs/liboqs-js

# yarn
yarn add @oqs/liboqs-js

# deno (via npm: specifier - no install needed)
# See "Deno Usage" section below
```

This project uses **bun** by default for development, but all package managers are fully supported.

### Deno Usage

✅ **Fully Supported** - Available through **npm** only due to package size limitations on JSR:

```typescript
// Alternative: Import from npm
import { createMLKEM768 } from "npm:@oqs/liboqs-js";

const kem = await createMLKEM768();
const { publicKey, secretKey } = kem.generateKeyPair();
kem.destroy();
```

**How it works:** The library automatically detects the Deno runtime and loads optimized WASM modules built for deno compatibility (`ENVIRONMENT='web'` Emscripten build).

**Recommended Setup** - Create a `deno.json` for cleaner imports:
```json
{
  "imports": {
    "liboqs": "npm:@oqs/liboqs-js@^0.15.1"
  }
}
```

Then import like:
```typescript
import { createMLKEM768 } from "liboqs";
```

**Using the CLI with Deno:**
```bash
# Run CLI directly (JSR)
deno run --allow-read npm:@oqs/liboqs-js/cli kem keygen ml-kem-768

# Or from npm
deno run --allow-read npm:@oqs/liboqs-js/cli kem keygen ml-kem-768
```

```json
# Or add to deno.json tasks:
{
  "tasks": {
    "liboqs": "deno run --allow-read npm:@oqs/liboqs-js/cli"
  }
}
```
```bash
# Then run:
deno task liboqs list --kem
```

**Permissions:**
```bash
# Library usage (cryptographic operations only)
deno run --allow-read your-script.ts

# CLI usage (may need write for output files)
deno run --allow-read --allow-write npm:@oqs/liboqs-js/cli kem keygen ml-kem-768 --output-dir ./keys
```

Deno automatically caches packages on first run - no separate install step needed.

## Requirements

- **Node.js 22.0 or higher** (for WASM SIMD support)
- **Package Managers**: Bun 1.0+, npm 10+, pnpm 8+, yarn 4+ (for Node.js)
- **Deno 2.0+** (available only through npm)
- **Modern browsers** with WebAssembly support (Chrome 91+, Firefox 89+, Edge 91+, Safari 16.4+ - Safari is untested)

## Quick Start

### Command Line Interface

The package includes a CLI for cryptographic operations without writing code:

```bash
# Generate ML-KEM-768 keypair
npx @oqs/liboqs-js kem keygen ml-kem-768 --output-dir ./keys

# Encapsulate to create shared secret
npx @oqs/liboqs-js kem encapsulate ml-kem-768 ./keys/public.key --format base64

# Sign a message
npx @oqs/liboqs-js sig sign ml-dsa-65 message.txt ./keys/secret.key -o signature.sig

# Verify signature
npx @oqs/liboqs-js sig verify ml-dsa-65 message.txt signature.sig ./keys/public.key

# List available algorithms
npx @oqs/liboqs-js list --kem

# Get algorithm info
npx @oqs/liboqs-js info ml-kem-768
```

**Works with all package managers:**
- `npx @oqs/liboqs-js` (npm)
- `bunx @oqs/liboqs-js` (bun)
- `pnpm dlx @oqs/liboqs-js` (pnpm)
- `yarn dlx @oqs/liboqs-js` (yarn)

**For full CLI documentation, run:**
```bash
npx @oqs/liboqs-js --help
```

### Key Encapsulation (ML-KEM)

```javascript
import { createMLKEM768 } from '@oqs/liboqs-js';

// Alice generates keypair
const alice = await createMLKEM768();
const { publicKey, secretKey } = alice.generateKeyPair();

// Bob encapsulates shared secret
const bob = await createMLKEM768();
const { ciphertext, sharedSecret } = bob.encapsulate(publicKey);

// Alice decapsulates
const aliceSecret = alice.decapsulate(ciphertext, secretKey);

// Verify shared secrets match
console.log('Secrets match:', Buffer.compare(sharedSecret, aliceSecret) === 0);

// Cleanup
alice.destroy();
bob.destroy();
```

### Digital Signatures (ML-DSA)

```javascript
import { createMLDSA65 } from '@oqs/liboqs-js';

const signer = await createMLDSA65();
const { publicKey, secretKey } = signer.generateKeyPair();

const message = new TextEncoder().encode('Hello, quantum world!');
const signature = signer.sign(message, secretKey);

const isValid = signer.verify(message, signature, publicKey);
console.log('Valid:', isValid); // true

signer.destroy();
```

## Available Algorithms

### NIST Standardized (Recommended)

These are the officially standardized post-quantum cryptographic algorithms approved by NIST for production use.

#### Key Encapsulation - ML-KEM (Module-Lattice-Based KEM)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| ML-KEM-512 | Level 1 (128-bit) | 800 B | 1,632 B | 768 B | `createMLKEM512()` |
| ML-KEM-768 | Level 3 (192-bit) | 1,184 B | 2,400 B | 1,088 B | `createMLKEM768()` |
| ML-KEM-1024 | Level 5 (256-bit) | 1,568 B | 3,168 B | 1,568 B | `createMLKEM1024()` |

**Formerly known as**: CRYSTALS-Kyber

#### Digital Signatures - ML-DSA (Module-Lattice-Based DSA)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| ML-DSA-44 | Level 2 (128-bit) | 1,312 B | 2,560 B | ~2,420 B | `createMLDSA44()` |
| ML-DSA-65 | Level 3 (192-bit) | 1,952 B | 4,032 B | ~3,309 B | `createMLDSA65()` |
| ML-DSA-87 | Level 5 (256-bit) | 2,592 B | 4,896 B | ~4,627 B | `createMLDSA87()` |

**Formerly known as**: CRYSTALS-Dilithium

#### Digital Signatures - SLH-DSA (Stateless Hash-Based DSA)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| SLH-DSA-SHA2-128f | Level 1 (128-bit) | 32 B | 64 B | 17,088 B | `createSLHDSASHA2128f()` |
| SLH-DSA-SHA2-128s | Level 1 (128-bit) | 32 B | 64 B | 7,856 B | `createSLHDSASHA2128s()` |
| SLH-DSA-SHA2-192f | Level 3 (192-bit) | 48 B | 96 B | 35,664 B | `createSLHDSASHA2192f()` |
| SLH-DSA-SHA2-192s | Level 3 (192-bit) | 48 B | 96 B | 16,224 B | `createSLHDSASHA2192s()` |
| SLH-DSA-SHA2-256f | Level 5 (256-bit) | 64 B | 128 B | 49,856 B | `createSLHDSASHA2256f()` |
| SLH-DSA-SHA2-256s | Level 5 (256-bit) | 64 B | 128 B | 29,792 B | `createSLHDSASHA2256s()` |
| SLH-DSA-SHAKE-128f | Level 1 (128-bit) | 32 B | 64 B | 17,088 B | `createSLHDSASHAKE128f()` |
| SLH-DSA-SHAKE-128s | Level 1 (128-bit) | 32 B | 64 B | 7,856 B | `createSLHDSASHAKE128s()` |
| SLH-DSA-SHAKE-192f | Level 3 (192-bit) | 48 B | 96 B | 35,664 B | `createSLHDSASHAKE192f()` |
| SLH-DSA-SHAKE-192s | Level 3 (192-bit) | 48 B | 96 B | 16,224 B | `createSLHDSASHAKE192s()` |
| SLH-DSA-SHAKE-256f | Level 5 (256-bit) | 64 B | 128 B | 49,856 B | `createSLHDSASHAKE256f()` |
| SLH-DSA-SHAKE-256s | Level 5 (256-bit) | 64 B | 128 B | 29,792 B | `createSLHDSASHAKE256s()` |

**Formerly known as**: SPHINCS+
**Variants**: `f` = fast signing/slower verification, `s` = small signatures/slower signing

### Additional Algorithms

Beyond the NIST-standardized algorithms, this library includes experimental and alternative post-quantum schemes for research purposes.

#### Legacy Kyber (Deprecated)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| Kyber512 | Level 1 (128-bit) | 800 B | 1,632 B | 768 B | `createKyber512()` |
| Kyber768 | Level 3 (192-bit) | 1,184 B | 2,400 B | 1,088 B | `createKyber768()` |
| Kyber1024 | Level 5 (256-bit) | 1,568 B | 3,168 B | 1,568 B | `createKyber1024()` |

**Note**: Use ML-KEM instead. Kyber is the pre-standardization version.

#### Key Encapsulation - Classic McEliece (10 variants)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| Classic-McEliece-348864 | Level 1 (128-bit) | 261,120 B | 6,492 B | 96 B | `createClassicMcEliece348864()` |
| Classic-McEliece-348864f | Level 1 (128-bit) | 261,120 B | 6,492 B | 96 B | `createClassicMcEliece348864f()` |
| Classic-McEliece-460896 | Level 3 (192-bit) | 524,160 B | 13,608 B | 156 B | `createClassicMcEliece460896()` |
| Classic-McEliece-460896f | Level 3 (192-bit) | 524,160 B | 13,608 B | 156 B | `createClassicMcEliece460896f()` |
| Classic-McEliece-6688128 | Level 5 (256-bit) | 1,044,992 B | 13,932 B | 208 B | `createClassicMcEliece6688128()` |
| Classic-McEliece-6688128f | Level 5 (256-bit) | 1,044,992 B | 13,932 B | 208 B | `createClassicMcEliece6688128f()` |
| Classic-McEliece-6960119 | Level 5 (256-bit) | 1,047,319 B | 13,948 B | 194 B | `createClassicMcEliece6960119()` |
| Classic-McEliece-6960119f | Level 5 (256-bit) | 1,047,319 B | 13,948 B | 194 B | `createClassicMcEliece6960119f()` |
| Classic-McEliece-8192128 | Level 5 (256-bit) | 1,357,824 B | 14,120 B | 208 B | `createClassicMcEliece8192128()` |
| Classic-McEliece-8192128f | Level 5 (256-bit) | 1,357,824 B | 14,120 B | 208 B | `createClassicMcEliece8192128f()` |

#### Key Encapsulation - FrodoKEM (6 salted variants)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| FrodoKEM-640-AES | Level 1 (128-bit) | 9,616 B | 19,888 B | 9,752 B | `createFrodoKEM640AES()` |
| FrodoKEM-640-SHAKE | Level 1 (128-bit) | 9,616 B | 19,888 B | 9,752 B | `createFrodoKEM640SHAKE()` |
| FrodoKEM-976-AES | Level 3 (192-bit) | 15,632 B | 31,296 B | 15,792 B | `createFrodoKEM976AES()` |
| FrodoKEM-976-SHAKE | Level 3 (192-bit) | 15,632 B | 31,296 B | 15,792 B | `createFrodoKEM976SHAKE()` |
| FrodoKEM-1344-AES | Level 5 (256-bit) | 21,520 B | 43,088 B | 21,696 B | `createFrodoKEM1344AES()` |
| FrodoKEM-1344-SHAKE | Level 5 (256-bit) | 21,520 B | 43,088 B | 21,696 B | `createFrodoKEM1344SHAKE()` |

#### Key Encapsulation - eFrodoKEM (6 ephemeral variants)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| eFrodoKEM-640-AES | Level 1 (128-bit) | 9,616 B | 19,888 B | 9,720 B | `createEFrodoKEM640AES()` |
| eFrodoKEM-640-SHAKE | Level 1 (128-bit) | 9,616 B | 19,888 B | 9,720 B | `createEFrodoKEM640SHAKE()` |
| eFrodoKEM-976-AES | Level 3 (192-bit) | 15,632 B | 31,296 B | 15,744 B | `createEFrodoKEM976AES()` |
| eFrodoKEM-976-SHAKE | Level 3 (192-bit) | 15,632 B | 31,296 B | 15,744 B | `createEFrodoKEM976SHAKE()` |
| eFrodoKEM-1344-AES | Level 5 (256-bit) | 21,520 B | 43,088 B | 21,632 B | `createEFrodoKEM1344AES()` |
| eFrodoKEM-1344-SHAKE | Level 5 (256-bit) | 21,520 B | 43,088 B | 21,632 B | `createEFrodoKEM1344SHAKE()` |

#### Key Encapsulation - HQC (3 variants)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| HQC-128 | Level 1 (128-bit) | 2,249 B | 2,305 B | 4,433 B | `createHQC128()` |
| HQC-192 | Level 3 (192-bit) | 4,522 B | 4,586 B | 8,978 B | `createHQC192()` |
| HQC-256 | Level 5 (256-bit) | 7,245 B | 7,317 B | 14,421 B | `createHQC256()` |

#### Key Encapsulation - NTRU (6 variants)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| NTRU-HPS-2048-509 | Level 1 (128-bit) | 699 B | 935 B | 699 B | `createNTRUHPS2048509()` |
| NTRU-HPS-2048-677 | Level 3 (192-bit) | 930 B | 1,234 B | 930 B | `createNTRUHPS2048677()` |
| NTRU-HPS-4096-821 | Level 5 (256-bit) | 1,230 B | 1,590 B | 1,230 B | `createNTRUHPS4096821()` |
| NTRU-HPS-4096-1229 | Level 5 (256-bit) | 1,842 B | 2,366 B | 1,842 B | `createNTRUHPS40961229()` |
| NTRU-HRSS-701 | Level 3 (192-bit) | 1,138 B | 1,450 B | 1,138 B | `createNTRUHRSS701()` |
| NTRU-HRSS-1373 | Level 5 (256-bit) | 2,401 B | 2,983 B | 2,401 B | `createNTRUHRSS1373()` |

#### Key Encapsulation - NTRU Prime

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Factory Function |
|-----------|----------------|------------|------------|------------|------------------|
| sntrup761 | Level 3 (192-bit) | 1,158 B | 1,763 B | 1,039 B | `createSntrup761()` |

**Note**: `sntrup761` is included primarily for interoperability testing.

#### Digital Signatures - Falcon (4 variants)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| Falcon-512 | Level 1 (128-bit) | 897 B | 1,281 B | ~752 B | `createFalcon512()` |
| Falcon-1024 | Level 5 (256-bit) | 1,793 B | 2,305 B | ~1,462 B | `createFalcon1024()` |
| Falcon-padded-512 | Level 1 (128-bit) | 897 B | 1,281 B | 666 B | `createFalconPadded512()` |
| Falcon-padded-1024 | Level 5 (256-bit) | 1,793 B | 2,305 B | 1,280 B | `createFalconPadded1024()` |

#### Digital Signatures - CROSS (18 variants)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| CROSS-rsdp-128-balanced | Level 1 (128-bit) | 77 B | 32 B | 13,152 B | `createCROSSRSDP128Balanced()` |
| CROSS-rsdp-128-fast | Level 1 (128-bit) | 77 B | 32 B | 18,432 B | `createCROSSRSDP128Fast()` |
| CROSS-rsdp-128-small | Level 1 (128-bit) | 77 B | 32 B | 12,432 B | `createCROSSRSDP128Small()` |
| CROSS-rsdp-192-balanced | Level 3 (192-bit) | 115 B | 48 B | 29,853 B | `createCROSSRSDP192Balanced()` |
| CROSS-rsdp-192-fast | Level 3 (192-bit) | 115 B | 48 B | 41,406 B | `createCROSSRSDP192Fast()` |
| CROSS-rsdp-192-small | Level 3 (192-bit) | 115 B | 48 B | 28,391 B | `createCROSSRSDP192Small()` |
| CROSS-rsdp-256-balanced | Level 5 (256-bit) | 153 B | 64 B | 53,527 B | `createCROSSRSDP256Balanced()` |
| CROSS-rsdp-256-fast | Level 5 (256-bit) | 153 B | 64 B | 74,590 B | `createCROSSRSDP256Fast()` |
| CROSS-rsdp-256-small | Level 5 (256-bit) | 153 B | 64 B | 50,818 B | `createCROSSRSDP256Small()` |
| CROSS-rsdpg-128-balanced | Level 1 (128-bit) | 54 B | 32 B | 9,120 B | `createCROSSRSDPG128Balanced()` |
| CROSS-rsdpg-128-fast | Level 1 (128-bit) | 54 B | 32 B | 11,980 B | `createCROSSRSDPG128Fast()` |
| CROSS-rsdpg-128-small | Level 1 (128-bit) | 54 B | 32 B | 8,960 B | `createCROSSRSDPG128Small()` |
| CROSS-rsdpg-192-balanced | Level 3 (192-bit) | 83 B | 48 B | 22,464 B | `createCROSSRSDPG192Balanced()` |
| CROSS-rsdpg-192-fast | Level 3 (192-bit) | 83 B | 48 B | 26,772 B | `createCROSSRSDPG192Fast()` |
| CROSS-rsdpg-192-small | Level 3 (192-bit) | 83 B | 48 B | 20,452 B | `createCROSSRSDPG192Small()` |
| CROSS-rsdpg-256-balanced | Level 5 (256-bit) | 106 B | 64 B | 40,100 B | `createCROSSRSDPG256Balanced()` |
| CROSS-rsdpg-256-fast | Level 5 (256-bit) | 106 B | 64 B | 48,102 B | `createCROSSRSDPG256Fast()` |
| CROSS-rsdpg-256-small | Level 5 (256-bit) | 106 B | 64 B | 36,454 B | `createCROSSRSDPG256Small()` |

#### Digital Signatures - MAYO (4 variants)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| MAYO-1 | Level 1 (128-bit) | 1,420 B | 24 B | 454 B | `createMAYO1()` |
| MAYO-2 | Level 1 (128-bit) | 4,912 B | 24 B | 186 B | `createMAYO2()` |
| MAYO-3 | Level 3 (192-bit) | 2,986 B | 32 B | 681 B | `createMAYO3()` |
| MAYO-5 | Level 5 (256-bit) | 5,554 B | 40 B | 964 B | `createMAYO5()` |

#### Digital Signatures - SNOVA (12 variants)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| SNOVA-24-5-4 | Level 1 (128-bit) | 1,016 B | 48 B | 248 B | `createSNOVA2454()` |
| SNOVA-24-5-4-esk | Level 1 (128-bit) | 1,016 B | 36,848 B | 248 B | `createSNOVA2454ESK()` |
| SNOVA-24-5-4-SHAKE | Level 1 (128-bit) | 1,016 B | 48 B | 248 B | `createSNOVA2454SHAKE()` |
| SNOVA-24-5-4-SHAKE-esk | Level 1 (128-bit) | 1,016 B | 36,848 B | 248 B | `createSNOVA2454SHAKEESK()` |
| SNOVA-24-5-5 | Level 1 (128-bit) | 1,579 B | 48 B | 379 B | `createSNOVA2455()` |
| SNOVA-25-8-3 | Level 1 (128-bit) | 2,320 B | 48 B | 165 B | `createSNOVA2583()` |
| SNOVA-29-6-5 | Level 3 (192-bit) | 2,716 B | 48 B | 454 B | `createSNOVA2965()` |
| SNOVA-37-17-2 | Level 3 (192-bit) | 9,842 B | 48 B | 124 B | `createSNOVA37172()` |
| SNOVA-37-8-4 | Level 3 (192-bit) | 4,112 B | 48 B | 376 B | `createSNOVA3784()` |
| SNOVA-49-11-3 | Level 5 (256-bit) | 6,006 B | 48 B | 286 B | `createSNOVA49113()` |
| SNOVA-56-25-2 | Level 5 (256-bit) | 31,266 B | 48 B | 178 B | `createSNOVA56252()` |
| SNOVA-60-10-4 | Level 5 (256-bit) | 8,016 B | 48 B | 576 B | `createSNOVA60104()` |

#### Digital Signatures - UOV (12 variants)

| Algorithm | Security Level | Public Key | Secret Key | Signature | Factory Function |
|-----------|----------------|------------|------------|-----------|------------------|
| OV-Ip | Level 1 (128-bit) | 278,432 B | 237,896 B | 128 B | `createOVIp()` |
| OV-Ip-pkc | Level 1 (128-bit) | 43,576 B | 237,896 B | 128 B | `createOVIpPKC()` |
| OV-Ip-pkc-skc | Level 1 (128-bit) | 43,576 B | 32 B | 128 B | `createOVIpPKCSKC()` |
| OV-Is | Level 1 (128-bit) | 412,160 B | 348,704 B | 96 B | `createOVIs()` |
| OV-Is-pkc | Level 1 (128-bit) | 66,576 B | 348,704 B | 96 B | `createOVIsPKC()` |
| OV-Is-pkc-skc | Level 1 (128-bit) | 66,576 B | 32 B | 96 B | `createOVIsPKCSKC()` |
| OV-III | Level 3 (192-bit) | 1,225,440 B | 1,044,320 B | 200 B | `createOVIII()` |
| OV-III-pkc | Level 3 (192-bit) | 189,232 B | 1,044,320 B | 200 B | `createOVIIIPKC()` |
| OV-III-pkc-skc | Level 3 (192-bit) | 189,232 B | 32 B | 200 B | `createOVIIIPKCSKC()` |
| OV-V | Level 5 (256-bit) | 2,869,440 B | 2,436,704 B | 260 B | `createOVV()` |
| OV-V-pkc | Level 5 (256-bit) | 446,992 B | 2,436,704 B | 260 B | `createOVVPKC()` |
| OV-V-pkc-skc | Level 5 (256-bit) | 446,992 B | 32 B | 260 B | `createOVVPKCSKC()` |

**Notes:**
- UOV variants with `-pkc` (public key compression) have smaller public keys
- UOV variants with `-skc` (secret key compression) have smaller secret keys
- `-esk` SNOVA variants use expanded secret keys for faster signing

## Bundle Size Optimization

Each algorithm is compiled separately into individual WASM modules, so you only bundle what you use:

```javascript
// Single algorithm (~80-160KB depending on algorithm complexity)
import { createMLKEM768 } from '@oqs/liboqs-js';
const kem = await createMLKEM768();

// Multiple algorithms - each adds its own WASM module
import { createMLKEM768, createMLDSA65 } from '@oqs/liboqs-js';
const kem = await createMLKEM768();
const sig = await createMLDSA65();
```

Tree-shaking ensures unused algorithms are never included in your bundle. Each algorithm's WASM is embedded in its module and loaded when you import the factory function.

## Package Structure

### Exports

```javascript
// Main entry - all 103 algorithm factory functions, classes, and metadata
import { createMLKEM768, MLKEM768, ML_KEM_768_INFO } from '@oqs/liboqs-js';

// KEM-only exports (32 algorithms)
import {
  createMLKEM512,
  createClassicMcEliece348864,
  createFrodoKEM640AES
} from '@oqs/liboqs-js/kem';

// Signature-only exports (65 algorithms)
import {
  createMLDSA44,
  createFalcon512,
  createSphincsSha2128fSimple
} from '@oqs/liboqs-js/sig';

// Error classes only
import { LibOQSError, LibOQSInitError } from '@oqs/liboqs-js/errors';
```

### File Structure

```
@oqs/liboqs-js/
├── src/
│   ├── algorithms/
│   │   ├── kem/
│   │   │   ├── ml-kem/           # ML-KEM (3 variants)
│   │   │   ├── kyber/            # Legacy Kyber (3 variants)
│   │   │   ├── classic-mceliece/ # Classic McEliece (10 variants)
│   │   │   ├── frodokem/         # FrodoKEM (6 variants)
│   │   │   ├── hqc/              # HQC (3 variants)
│   │   │   └── ntru/             # NTRU + sntrup761 (7 variants)
│   │   └── sig/
│   │       ├── ml-dsa/           # ML-DSA (3 variants)
│   │       ├── falcon/           # Falcon (4 variants)
│   │       ├── slh-dsa/          # SLH-DSA (12 variants)
│   │       ├── cross/            # CROSS (18 variants)
│   │       ├── mayo/             # MAYO (4 variants)
│   │       ├── snova/            # SNOVA (12 variants)
│   │       └── uov/              # UOV (12 variants)
│   ├── cli/
│   │   ├── commands/             # CLI command implementations
│   │   │   ├── info.js           # Algorithm information
│   │   │   ├── kem.js            # KEM operations (keygen, encaps, decaps)
│   │   │   ├── sig.js            # Signature operations (keygen, sign, verify)
│   │   │   └── list.js           # List available algorithms
│   │   ├── algorithms.js         # Algorithm registry
│   │   ├── index.js              # CLI entry point
│   │   ├── io.js                 # File I/O utilities
│   │   └── parser.js             # Command parser
│   ├── core/
│   │   ├── errors.js             # Error classes
│   │   └── validation.js         # Input validation utilities
│   ├── types/                    # TypeScript definitions
│   │   ├── algorithms.d.ts
│   │   ├── errors.d.ts
│   │   └── index.d.ts
│   ├── index.js                  # Main entry (all 103 algorithms)
│   ├── kem.js                    # KEM exports (38 algorithms)
│   └── sig.js                    # Signature exports (65 algorithms)
├── bin/
│   └── cli.js                    # CLI executable entry point
├── tests/
│   ├── kem.test.ts
│   ├── sig.test.ts
│   ├── cli.test.ts
│   └── deno/                     # Deno-specific tests
│       ├── kem.test.ts
│       ├── sig.test.ts
│       └── cli.test.ts
├── dist/                         # WASM modules (97 × 2 = 194 files, ~100-500KB each)
│   ├── ml-kem-512.min.js         # Node.js/Browser module
│   ├── ml-kem-512.deno.js        # Deno module
│   ├── falcon-512.min.js
│   ├── falcon-512.deno.js
│   └── ... (and 190 others)
├── algorithms.json               # Algorithm registry and metadata
└── build.sh                      # WASM build script
```

## Architecture

The library is organized in layers:

1. **WASM Modules**: Emscripten-compiled LibOQS binaries (one per algorithm)
2. **Low-level Bindings**: Direct WASM function calls (`_OQS_KEM_*`, `_OQS_SIG_*`)
3. **High-level Wrappers**: User-friendly classes (`MLKEM768`, `MLDSA65`)
4. **Public API**: Factory functions and exports

### Memory Management

**IMPORTANT**: Always call `destroy()` when finished with an algorithm instance. WASM memory is not garbage-collected by JavaScript.

#### Why This Matters

WebAssembly modules allocate native memory outside the JavaScript heap. When you create an algorithm instance, LibOQS allocates C structures that JavaScript's garbage collector cannot reclaim. Without calling `destroy()`, this memory leaks permanently.

**Long-running applications** (servers, single-page apps, daemons) that don't call `destroy()` will experience:
- Increasing memory usage over time
- Eventually: allocation failures or crashes when the 256MB WASM heap limit is reached

**Short-lived scripts** are less affected since the OS reclaims all memory when the process exits.

#### Best Practices

```javascript
// Pattern 1: Simple cleanup
const kem = await createMLKEM768();
const { publicKey, secretKey } = kem.generateKeyPair();
kem.destroy();

// Pattern 2: Error-safe cleanup (recommended)
const kem = await createMLKEM768();
try {
  const { publicKey, secretKey } = kem.generateKeyPair();
  const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
  // ... use results ...
} finally {
  kem.destroy(); // Always runs, even if errors occur
}

// Pattern 3: Multiple operations
const sig = await createMLDSA65();
try {
  const { publicKey, secretKey } = sig.generateKeyPair();
  const message = new TextEncoder().encode('Hello!');
  const signature = sig.sign(message, secretKey);
  const isValid = sig.verify(message, signature, publicKey);
  return isValid;
} finally {
  sig.destroy();
}
```

#### Additional Notes

- Secret keys, shared secrets, and signatures are handled via WASM memory
- Keys and secrets are not automatically zeroed (limitation of JavaScript/WASM)
- Each algorithm instance must be destroyed individually
- After calling `destroy()`, the instance cannot be reused

### Thread Safety

- Individual algorithm instances are **not** thread-safe
- For concurrent operations, create separate instances per worker/thread
- WASM modules can be instantiated multiple times safely

## Security Considerations

1. **Use NIST Standardized Algorithms**: ML-KEM, ML-DSA, and SLH-DSA are recommended for production
2. **Hybrid Cryptography**: We, as well as OQS, strongly recommend combining with traditional algorithms (X25519/Ed25519) during transition
3. **Key Storage**: Store secret keys securely, never in plain text or localStorage
4. **Stay Updated**: Monitor NIST guidance and update regularly
5. **Audit Your Deployment**: Consult cryptographic experts for production use
6. **Random Number Generation**: This library uses system entropy (Node.js `crypto.randomBytes()`, browser `crypto.getRandomValues()`)

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy. Issues specific to the LibOQS C library should be reported to the [LibOQS project](https://github.com/open-quantum-safe/liboqs/security).

## Building from Source

### Prerequisites

- **Node.js 22+**
- **Emscripten** (latest stable release)
- **Git**
- **CMake 3.20+**
- **Python 3** (for Emscripten)
- **jq** (for JSON parsing in build.sh)

### Build Steps

```bash
# Clone repository
git clone https://github.com/open-quantum-safe/liboqs-js.git
cd liboqs-js

# Build all algorithms
./build.sh

# Build specific algorithm
./build.sh ml-kem-768

# Setup only (clone liboqs without building)
./build.sh --setup-only

# Clean build artifacts
./build.sh --clean
```

### Build System

The build system is **data-driven** using `algorithms.json`:

```json
{
  "kem": {
    "ml-kem": {
      "ML-KEM-768": {
        "slug": "ml-kem-768",
        "cmake_var": "ML_KEM_768",
        "security": 3,
        "standardized": true
      }
    }
  }
}
```

The `build.sh` script:
1. Parses `algorithms.json` with jq
2. Dynamically generates CMake flags to build single-algorithm WASM modules
3. Compiles with Emscripten optimizations (Closure compiler, WASM SIMD)
4. Outputs standalone `.min.js` files with embedded WASM

**No build script changes needed to add new algorithms** - just update the JSON registry.

### Adding New Algorithms

#### Quick Start

```bash
# 1. Add algorithm metadata to algorithms.json
# 2. Create the algorithm wrapper file (see existing files for patterns)
# 3. Build WASM module
./build.sh <algorithm-slug>

# 4. Export from src/index.js, src/kem.js, or src/sig.js
```

#### Key Size Management

The `fetch-key-sizes.js` script extracts key sizes from existing algorithm files and updates `algorithms.json`:

```bash
node scripts/fetch-key-sizes.js
# Scans src/algorithms/**/*.js for keySize data
# Updates algorithms.json with found key sizes
```

This is useful when:
- Updating key sizes after LibOQS version changes
- Ensuring consistency across the codebase
- Adding new algorithms

#### Steps

1. **Add to `algorithms.json`**: Include the algorithm metadata (slug, cmake_var, security level, key sizes)
2. **Create wrapper file**: Follow patterns in existing files under `src/algorithms/kem/` or `src/algorithms/sig/`
3. **Export in index files**: Add to `src/index.js`, `src/kem.js`, or `src/sig.js`
4. **Add tests**: Follow patterns in `tests/kem.test.ts` or `tests/sig.test.ts`
5. **Update TypeScript definitions**: If needed, update `src/types/algorithms.d.ts`

All 103 algorithms maintain consistent APIs, documentation, and error handling patterns.

## Testing

The library includes comprehensive test coverage using Vitest:

```bash
# Run all tests (1400+ tests across 103 algorithms for both node and browser environments)
bun test

# Or use your preferred package manager
npm test
pnpm test
yarn test

# Or with Deno:
deno test --allow-read --allow-write --allow-run --allow-env --no-check tests/deno/
```

Test coverage includes:
- **Algorithm correctness**: All algorithms tested for basic functionality
- **Round-trip verification**: KEM encapsulation/decapsulation, signature sign/verify
- **Key generation**: Validates key sizes match specifications
- **Cross-environment**: Node.js and browser (jsdom) compatibility
- **Error handling**: Validates proper error messages and types
- **Memory safety**: Ensures cleanup via destroy() methods
- **Edge cases**: Empty messages, invalid signatures, destroyed instances

## Contributing

Contributions are welcome! Please:

- **Tests must pass**: Run `bun run test` (or `npm run test`) and `deno test --allow-read --allow-write --allow-run --allow-env --no-check tests/deno/` before submitting
- **Follow existing code style**: Use ESM, async/await, JSDoc comments
- **Document public APIs**: Add comprehensive JSDoc for all exported functions and classes
- **Security first**: Consider security implications, especially for cryptographic operations
- **Consistency matters**: Follow established patterns in existing wrappers

For larger changes, open an issue first to discuss the approach.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Install dependencies: `bun install` (or `npm install`, `pnpm install`, etc.)
4. Make your changes (add tests if applicable)
5. Run tests: `bun run test` (or `npm run test`)
6. Build and test locally
7. Submit a pull request

### Package Manager Notes

```bash
# Using bun (recommended/default for contributors)
bun install
bun run test
bun run build

# Using npm
npm install
npm run test
npm run build

# Using pnpm
pnpm install
pnpm runtest
pnpm run build

# Using yarn
yarn install
yarn run test
yarn run build
```

Contributions that add new algorithm wrappers, improve documentation, add tests, or enhance the build system are especially appreciated.

## Documentation

- **[Security Policy](SECURITY.md)** - Vulnerability reporting and security guidance
- **[LibOQS Documentation](https://github.com/open-quantum-safe/liboqs)** - Underlying C library

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) project for LibOQS
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- The cryptographic research community
- Emscripten team for excellent WASM tooling

## Versioning

This library's version tracks the bundled LibOQS version:
- `@oqs/liboqs-js 0.15.x` includes `LibOQS 0.15.1`

## Disclaimer

This library provides access to cryptographic algorithms believed to be quantum-resistant based on current research. The field of post-quantum cryptography is evolving. Algorithm support may change as research advances. Always consult with cryptographic experts for production deployments and follow NIST recommendations.

The LibOQS project states: **"WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA."** This guidance applies to this JavaScript/WebAssembly wrapper as well.
