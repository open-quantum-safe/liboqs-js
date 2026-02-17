/**
 * @fileoverview TypeScript definitions for individual algorithm modules
 * @description Per-algorithm WASM module type definitions
 */

// Base WASM module interface
export interface BaseWASMModule {
  // Core lifecycle
  _OQS_init(): void;
  _OQS_destroy(): void;

  // Memory management
  _malloc(size: number): number;
  _free(ptr: number): void;
  _OQS_MEM_malloc(size: number): number;
  _OQS_MEM_secure_free(ptr: number, size: number): void;

  // Random number generation (requires setup in embedded build)
  _OQS_randombytes(ptr: number, len: number): void;

  // Emscripten runtime methods
  UTF8ToString(ptr: number, maxLength?: number): string;
  stringToUTF8(str: string, ptr: number, maxLength: number): number;
  lengthBytesUTF8(str: string): number;
  getValue(ptr: number, type: string): number;
  setValue(ptr: number, value: number, type: string): void;
  HEAPU8: Uint8Array;
  HEAP32: Int32Array;
}

// KEM-specific operations
export interface KEMModule extends BaseWASMModule {
  _OQS_KEM_new(name: string): number;
  _OQS_KEM_free(kem: number): void;
  _OQS_KEM_keypair(kem: number, public_key: number, secret_key: number): number;
  _OQS_KEM_encaps(kem: number, ciphertext: number, shared_secret: number, public_key: number): number;
  _OQS_KEM_decaps(kem: number, shared_secret: number, ciphertext: number, secret_key: number): number;
}

// Signature-specific operations
export interface SIGModule extends BaseWASMModule {
  _OQS_MEM_cleanse(ptr: number, size: number): void;
  _OQS_SIG_new(name: string): number;
  _OQS_SIG_free(sig: number): void;
  _OQS_SIG_keypair(sig: number, public_key: number, secret_key: number): number;
  _OQS_SIG_sign(sig: number, signature: number, signature_len: number, message: number, message_len: number, secret_key: number): number;
  _OQS_SIG_verify(sig: number, message: number, message_len: number, signature: number, signature_len: number, public_key: number): number;
}

// ML-KEM specific modules
export interface MLKEM512Module extends KEMModule { }
export interface MLKEM768Module extends KEMModule { }
export interface MLKEM1024Module extends KEMModule { }

// Kyber specific modules (deprecated)
export interface Kyber512Module extends KEMModule { }
export interface Kyber768Module extends KEMModule { }
export interface Kyber1024Module extends KEMModule { }

// FrodoKEM specific modules
export interface FrodoKEM640AESModule extends KEMModule { }
export interface FrodoKEM640SHAKEModule extends KEMModule { }
export interface FrodoKEM976AESModule extends KEMModule { }
export interface FrodoKEM976SHAKEModule extends KEMModule { }
export interface FrodoKEM1344AESModule extends KEMModule { }
export interface FrodoKEM1344SHAKEModule extends KEMModule { }

// eFrodoKEM specific modules
export interface EFrodoKEM640AESModule extends KEMModule { }
export interface EFrodoKEM640SHAKEModule extends KEMModule { }
export interface EFrodoKEM976AESModule extends KEMModule { }
export interface EFrodoKEM976SHAKEModule extends KEMModule { }
export interface EFrodoKEM1344AESModule extends KEMModule { }
export interface EFrodoKEM1344SHAKEModule extends KEMModule { }

// HQC specific modules
export interface HQC128Module extends KEMModule { }
export interface HQC192Module extends KEMModule { }
export interface HQC256Module extends KEMModule { }

// Classic McEliece specific modules
export interface ClassicMcEliece348864Module extends KEMModule { }
export interface ClassicMcEliece348864fModule extends KEMModule { }
export interface ClassicMcEliece460896Module extends KEMModule { }
export interface ClassicMcEliece460896fModule extends KEMModule { }
export interface ClassicMcEliece6688128Module extends KEMModule { }
export interface ClassicMcEliece6688128fModule extends KEMModule { }
export interface ClassicMcEliece6960119Module extends KEMModule { }
export interface ClassicMcEliece6960119fModule extends KEMModule { }
export interface ClassicMcEliece8192128Module extends KEMModule { }
export interface ClassicMcEliece8192128fModule extends KEMModule { }

// NTRU specific modules
export interface NTRUHps2048509Module extends KEMModule { }
export interface NTRUHps2048677Module extends KEMModule { }
export interface NTRUHps4096821Module extends KEMModule { }
export interface NTRUHps40961229Module extends KEMModule { }
export interface NTRUHrss701Module extends KEMModule { }
export interface NTRUHrss1373Module extends KEMModule { }
export interface Sntrup761Module extends KEMModule { }

// ML-DSA specific modules
export interface MLDSA44Module extends SIGModule { }
export interface MLDSA65Module extends SIGModule { }
export interface MLDSA87Module extends SIGModule { }

// Falcon specific modules
export interface Falcon512Module extends SIGModule { }
export interface Falcon1024Module extends SIGModule { }
export interface FalconPadded512Module extends SIGModule { }
export interface FalconPadded1024Module extends SIGModule { }

// MAYO specific modules
export interface MAYO1Module extends SIGModule { }
export interface MAYO2Module extends SIGModule { }
export interface MAYO3Module extends SIGModule { }
export interface MAYO5Module extends SIGModule { }

// UOV specific modules
export interface OVIpModule extends SIGModule { }
export interface OVIpPkcModule extends SIGModule { }
export interface OVIpPkcSkcModule extends SIGModule { }
export interface OVIsModule extends SIGModule { }
export interface OVIsPkcModule extends SIGModule { }
export interface OVIsPkcSkcModule extends SIGModule { }
export interface OVIIIModule extends SIGModule { }
export interface OVIIIPkcModule extends SIGModule { }
export interface OVIIIPkcSkcModule extends SIGModule { }
export interface OVVModule extends SIGModule { }
export interface OVVPkcModule extends SIGModule { }
export interface OVVPkcSkcModule extends SIGModule { }

// CROSS specific modules
export interface CrossRsdp128BalancedModule extends SIGModule { }
export interface CrossRsdp128FastModule extends SIGModule { }
export interface CrossRsdp128SmallModule extends SIGModule { }
export interface CrossRsdp192BalancedModule extends SIGModule { }
export interface CrossRsdp192FastModule extends SIGModule { }
export interface CrossRsdp192SmallModule extends SIGModule { }
export interface CrossRsdp256BalancedModule extends SIGModule { }
export interface CrossRsdp256FastModule extends SIGModule { }
export interface CrossRsdp256SmallModule extends SIGModule { }
export interface CrossRsdpg128BalancedModule extends SIGModule { }
export interface CrossRsdpg128FastModule extends SIGModule { }
export interface CrossRsdpg128SmallModule extends SIGModule { }
export interface CrossRsdpg192BalancedModule extends SIGModule { }
export interface CrossRsdpg192FastModule extends SIGModule { }
export interface CrossRsdpg192SmallModule extends SIGModule { }
export interface CrossRsdpg256BalancedModule extends SIGModule { }
export interface CrossRsdpg256FastModule extends SIGModule { }
export interface CrossRsdpg256SmallModule extends SIGModule { }

// SLH-DSA specific modules (FIPS 205)
export interface SlhDsaSha2128fModule extends SIGModule { }
export interface SlhDsaSha2128sModule extends SIGModule { }
export interface SlhDsaSha2192fModule extends SIGModule { }
export interface SlhDsaSha2192sModule extends SIGModule { }
export interface SlhDsaSha2256fModule extends SIGModule { }
export interface SlhDsaSha2256sModule extends SIGModule { }
export interface SlhDsaShake128fModule extends SIGModule { }
export interface SlhDsaShake128sModule extends SIGModule { }
export interface SlhDsaShake192fModule extends SIGModule { }
export interface SlhDsaShake192sModule extends SIGModule { }
export interface SlhDsaShake256fModule extends SIGModule { }
export interface SlhDsaShake256sModule extends SIGModule { }

// SNOVA specific modules
export interface Snova2454Module extends SIGModule { }
export interface Snova2454EskModule extends SIGModule { }
export interface Snova2454ShakeModule extends SIGModule { }
export interface Snova2454ShakeEskModule extends SIGModule { }
export interface Snova2455Module extends SIGModule { }
export interface Snova2583Module extends SIGModule { }
export interface Snova2965Module extends SIGModule { }
export interface Snova37172Module extends SIGModule { }
export interface Snova3784Module extends SIGModule { }
export interface Snova49113Module extends SIGModule { }
export interface Snova56252Module extends SIGModule { }
export interface Snova60104Module extends SIGModule { }

// Module factory type
export type WASMModuleFactory<T = BaseWASMModule> = (moduleOverrides?: Record<string, unknown>) => Promise<T>;

// Algorithm identifiers
export type KEMAlgorithm =
  | 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024'
  | 'kyber-512' | 'kyber-768' | 'kyber-1024'
  | 'frodokem-640-aes' | 'frodokem-640-shake' | 'frodokem-976-aes' | 'frodokem-976-shake' | 'frodokem-1344-aes' | 'frodokem-1344-shake'
  | 'hqc-128' | 'hqc-192' | 'hqc-256'
  | 'classic-mceliece-348864' | 'classic-mceliece-348864f'
  | 'classic-mceliece-460896' | 'classic-mceliece-460896f'
  | 'classic-mceliece-6688128' | 'classic-mceliece-6688128f'
  | 'classic-mceliece-6960119' | 'classic-mceliece-6960119f'
  | 'classic-mceliece-8192128' | 'classic-mceliece-8192128f'
  | 'ntru-hps-2048-509' | 'ntru-hps-2048-677' | 'ntru-hps-4096-821' | 'ntru-hps-4096-1229'
  | 'ntru-hrss-701' | 'ntru-hrss-1373'
  | 'sntrup761';
export type SIGAlgorithm = 'ml-dsa-44' | 'ml-dsa-65' | 'ml-dsa-87' | 'falcon-512' | 'falcon-1024' | 'falcon-padded-512' | 'falcon-padded-1024'
  | 'mayo-1' | 'mayo-2' | 'mayo-3' | 'mayo-5'
  | 'ov-ip' | 'ov-ip-pkc' | 'ov-ip-pkc-skc' | 'ov-is' | 'ov-is-pkc' | 'ov-is-pkc-skc' | 'ov-iii' | 'ov-iii-pkc' | 'ov-iii-pkc-skc' | 'ov-v' | 'ov-v-pkc' | 'ov-v-pkc-skc'
  | 'cross-rsdp-128-balanced' | 'cross-rsdp-128-fast' | 'cross-rsdp-128-small' | 'cross-rsdp-192-balanced' | 'cross-rsdp-192-fast' | 'cross-rsdp-192-small' | 'cross-rsdp-256-balanced' | 'cross-rsdp-256-fast' | 'cross-rsdp-256-small' | 'cross-rsdpg-128-balanced' | 'cross-rsdpg-128-fast' | 'cross-rsdpg-128-small' | 'cross-rsdpg-192-balanced' | 'cross-rsdpg-192-fast' | 'cross-rsdpg-192-small' | 'cross-rsdpg-256-balanced' | 'cross-rsdpg-256-fast' | 'cross-rsdpg-256-small'
  | 'slh-dsa-sha2-128f' | 'slh-dsa-sha2-128s' | 'slh-dsa-sha2-192f' | 'slh-dsa-sha2-192s' | 'slh-dsa-sha2-256f' | 'slh-dsa-sha2-256s' | 'slh-dsa-shake-128f' | 'slh-dsa-shake-128s' | 'slh-dsa-shake-192f' | 'slh-dsa-shake-192s' | 'slh-dsa-shake-256f' | 'slh-dsa-shake-256s'
  | 'snova-24-5-4' | 'snova-24-5-4-esk' | 'snova-24-5-4-shake' | 'snova-24-5-4-shake-esk' | 'snova-24-5-5' | 'snova-25-8-3'
  | 'snova-29-6-5' | 'snova-37-17-2' | 'snova-37-8-4'
  | 'snova-49-11-3' | 'snova-56-25-2' | 'snova-60-10-4';
export type Algorithm = KEMAlgorithm | SIGAlgorithm;

// Algorithm metadata
export interface AlgorithmInfo {
  name: string;
  identifier: string;
  type: 'kem' | 'sig';
  securityLevel: 1 | 2 | 3 | 4 | 5;
  standardized: boolean;
  deprecated?: boolean;
  description: string;
  keySize: {
    publicKey: number;
    secretKey: number;
    ciphertext?: number;
    sharedSecret?: number;
    signature?: number;
  };
}

// High-level algorithm interfaces
export interface KEMResult {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface EncapsResult {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export interface SIGResult {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// Generic instance interfaces for all KEM and SIG algorithms
export interface KEMInstance {
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export interface SIGInstance {
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// Factory function types
export type KEMFactory<T extends KEMInstance = KEMInstance> = () => Promise<T>;
export type SIGFactory<T extends SIGInstance = SIGInstance> = () => Promise<T>;

// ML-KEM wrapper classes
export declare class MLKEM512 {
  constructor(wasmModule: MLKEM512Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MLKEM768 {
  constructor(wasmModule: MLKEM768Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MLKEM1024 {
  constructor(wasmModule: MLKEM1024Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// Kyber wrapper classes (deprecated)
export declare class Kyber512 {
  constructor(wasmModule: Kyber512Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Kyber768 {
  constructor(wasmModule: Kyber768Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Kyber1024 {
  constructor(wasmModule: Kyber1024Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// FrodoKEM wrapper classes
export declare class FrodoKEM640AES {
  constructor(wasmModule: FrodoKEM640AESModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FrodoKEM640SHAKE {
  constructor(wasmModule: FrodoKEM640SHAKEModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FrodoKEM976AES {
  constructor(wasmModule: FrodoKEM976AESModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FrodoKEM976SHAKE {
  constructor(wasmModule: FrodoKEM976SHAKEModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FrodoKEM1344AES {
  constructor(wasmModule: FrodoKEM1344AESModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FrodoKEM1344SHAKE {
  constructor(wasmModule: FrodoKEM1344SHAKEModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// eFrodoKEM wrapper classes
export declare class EFrodoKEM640AES {
  constructor(wasmModule: EFrodoKEM640AESModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class EFrodoKEM640SHAKE {
  constructor(wasmModule: EFrodoKEM640SHAKEModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class EFrodoKEM976AES {
  constructor(wasmModule: EFrodoKEM976AESModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class EFrodoKEM976SHAKE {
  constructor(wasmModule: EFrodoKEM976SHAKEModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class EFrodoKEM1344AES {
  constructor(wasmModule: EFrodoKEM1344AESModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class EFrodoKEM1344SHAKE {
  constructor(wasmModule: EFrodoKEM1344SHAKEModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// HQC wrapper classes
export declare class HQC128 {
  constructor(wasmModule: HQC128Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class HQC192 {
  constructor(wasmModule: HQC192Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class HQC256 {
  constructor(wasmModule: HQC256Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// Classic McEliece wrapper classes
export declare class ClassicMcEliece348864 {
  constructor(wasmModule: ClassicMcEliece348864Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece348864f {
  constructor(wasmModule: ClassicMcEliece348864fModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece460896 {
  constructor(wasmModule: ClassicMcEliece460896Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece460896f {
  constructor(wasmModule: ClassicMcEliece460896fModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece6688128 {
  constructor(wasmModule: ClassicMcEliece6688128Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece6688128f {
  constructor(wasmModule: ClassicMcEliece6688128fModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece6960119 {
  constructor(wasmModule: ClassicMcEliece6960119Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece6960119f {
  constructor(wasmModule: ClassicMcEliece6960119fModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece8192128 {
  constructor(wasmModule: ClassicMcEliece8192128Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class ClassicMcEliece8192128f {
  constructor(wasmModule: ClassicMcEliece8192128fModule, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// NTRU wrapper classes
export declare class NTRUHps2048509 {
  constructor(wasmModule: NTRUHps2048509Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class NTRUHps2048677 {
  constructor(wasmModule: NTRUHps2048677Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class NTRUHps4096821 {
  constructor(wasmModule: NTRUHps4096821Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class NTRUHps40961229 {
  constructor(wasmModule: NTRUHps40961229Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class NTRUHrss701 {
  constructor(wasmModule: NTRUHrss701Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class NTRUHrss1373 {
  constructor(wasmModule: NTRUHrss1373Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Sntrup761 {
  constructor(wasmModule: Sntrup761Module, kemPtr: number);
  generateKeyPair(): KEMResult;
  encapsulate(publicKey: Uint8Array): EncapsResult;
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// ML-DSA wrapper classes
export declare class MLDSA44 {
  constructor(wasmModule: MLDSA44Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MLDSA65 {
  constructor(wasmModule: MLDSA65Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MLDSA87 {
  constructor(wasmModule: MLDSA87Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// Falcon wrapper classes
export declare class Falcon512 {
  constructor(wasmModule: Falcon512Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Falcon1024 {
  constructor(wasmModule: Falcon1024Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FalconPadded512 {
  constructor(wasmModule: FalconPadded512Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class FalconPadded1024 {
  constructor(wasmModule: FalconPadded1024Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// MAYO wrapper classes
export declare class MAYO1 {
  constructor(wasmModule: MAYO1Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MAYO2 {
  constructor(wasmModule: MAYO2Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MAYO3 {
  constructor(wasmModule: MAYO3Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class MAYO5 {
  constructor(wasmModule: MAYO5Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// UOV wrapper classes
export declare class OVIp {
  constructor(wasmModule: OVIpModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIpPkc {
  constructor(wasmModule: OVIpPkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIpPkcSkc {
  constructor(wasmModule: OVIpPkcSkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIs {
  constructor(wasmModule: OVIsModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIsPkc {
  constructor(wasmModule: OVIsPkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIsPkcSkc {
  constructor(wasmModule: OVIsPkcSkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIII {
  constructor(wasmModule: OVIIIModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIIIPkc {
  constructor(wasmModule: OVIIIPkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVIIIPkcSkc {
  constructor(wasmModule: OVIIIPkcSkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVV {
  constructor(wasmModule: OVVModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVVPkc {
  constructor(wasmModule: OVVPkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class OVVPkcSkc {
  constructor(wasmModule: OVVPkcSkcModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// CROSS wrapper classes
export declare class CrossRsdp128Balanced {
  constructor(wasmModule: CrossRsdp128BalancedModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp128Fast {
  constructor(wasmModule: CrossRsdp128FastModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp128Small {
  constructor(wasmModule: CrossRsdp128SmallModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp192Balanced {
  constructor(wasmModule: CrossRsdp192BalancedModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp192Fast {
  constructor(wasmModule: CrossRsdp192FastModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp192Small {
  constructor(wasmModule: CrossRsdp192SmallModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp256Balanced {
  constructor(wasmModule: CrossRsdp256BalancedModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp256Fast {
  constructor(wasmModule: CrossRsdp256FastModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdp256Small {
  constructor(wasmModule: CrossRsdp256SmallModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg128Balanced {
  constructor(wasmModule: CrossRsdpg128BalancedModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg128Fast {
  constructor(wasmModule: CrossRsdpg128FastModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg128Small {
  constructor(wasmModule: CrossRsdpg128SmallModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg192Balanced {
  constructor(wasmModule: CrossRsdpg192BalancedModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg192Fast {
  constructor(wasmModule: CrossRsdpg192FastModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg192Small {
  constructor(wasmModule: CrossRsdpg192SmallModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg256Balanced {
  constructor(wasmModule: CrossRsdpg256BalancedModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg256Fast {
  constructor(wasmModule: CrossRsdpg256FastModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class CrossRsdpg256Small {
  constructor(wasmModule: CrossRsdpg256SmallModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// SLH-DSA wrapper classes (FIPS 205)
export declare class SlhDsaSha2128f {
  constructor(wasmModule: SlhDsaSha2128fModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaSha2128s {
  constructor(wasmModule: SlhDsaSha2128sModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaSha2192f {
  constructor(wasmModule: SlhDsaSha2192fModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaSha2192s {
  constructor(wasmModule: SlhDsaSha2192sModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaSha2256f {
  constructor(wasmModule: SlhDsaSha2256fModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaSha2256s {
  constructor(wasmModule: SlhDsaSha2256sModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaShake128f {
  constructor(wasmModule: SlhDsaShake128fModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaShake128s {
  constructor(wasmModule: SlhDsaShake128sModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaShake192f {
  constructor(wasmModule: SlhDsaShake192fModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaShake192s {
  constructor(wasmModule: SlhDsaShake192sModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaShake256f {
  constructor(wasmModule: SlhDsaShake256fModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class SlhDsaShake256s {
  constructor(wasmModule: SlhDsaShake256sModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// SNOVA wrapper classes
export declare class Snova2454 {
  constructor(wasmModule: Snova2454Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova2454Esk {
  constructor(wasmModule: Snova2454EskModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova2454Shake {
  constructor(wasmModule: Snova2454ShakeModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova2454ShakeEsk {
  constructor(wasmModule: Snova2454ShakeEskModule, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova2455 {
  constructor(wasmModule: Snova2455Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova2583 {
  constructor(wasmModule: Snova2583Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova2965 {
  constructor(wasmModule: Snova2965Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova37172 {
  constructor(wasmModule: Snova37172Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova3784 {
  constructor(wasmModule: Snova3784Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova49113 {
  constructor(wasmModule: Snova49113Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova56252 {
  constructor(wasmModule: Snova56252Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

export declare class Snova60104 {
  constructor(wasmModule: Snova60104Module, sigPtr: number);
  generateKeyPair(): SIGResult;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  destroy(): void;
  [Symbol.dispose](): void;
  readonly info: Readonly<AlgorithmInfo>;
}

// Factory functions
export declare function createMLKEM512(): Promise<MLKEM512>;
export declare function createMLKEM768(): Promise<MLKEM768>;
export declare function createMLKEM1024(): Promise<MLKEM1024>;

export declare function createKyber512(): Promise<Kyber512>;
export declare function createKyber768(): Promise<Kyber768>;
export declare function createKyber1024(): Promise<Kyber1024>;

export declare function createFrodoKEM640AES(): Promise<FrodoKEM640AES>;
export declare function createFrodoKEM640SHAKE(): Promise<FrodoKEM640SHAKE>;
export declare function createFrodoKEM976AES(): Promise<FrodoKEM976AES>;
export declare function createFrodoKEM976SHAKE(): Promise<FrodoKEM976SHAKE>;
export declare function createFrodoKEM1344AES(): Promise<FrodoKEM1344AES>;
export declare function createFrodoKEM1344SHAKE(): Promise<FrodoKEM1344SHAKE>;

export declare function createEFrodoKEM640AES(): Promise<EFrodoKEM640AES>;
export declare function createEFrodoKEM640SHAKE(): Promise<EFrodoKEM640SHAKE>;
export declare function createEFrodoKEM976AES(): Promise<EFrodoKEM976AES>;
export declare function createEFrodoKEM976SHAKE(): Promise<EFrodoKEM976SHAKE>;
export declare function createEFrodoKEM1344AES(): Promise<EFrodoKEM1344AES>;
export declare function createEFrodoKEM1344SHAKE(): Promise<EFrodoKEM1344SHAKE>;

export declare function createHQC128(): Promise<HQC128>;
export declare function createHQC192(): Promise<HQC192>;
export declare function createHQC256(): Promise<HQC256>;

export declare function createClassicMcEliece348864(): Promise<ClassicMcEliece348864>;
export declare function createClassicMcEliece348864f(): Promise<ClassicMcEliece348864f>;
export declare function createClassicMcEliece460896(): Promise<ClassicMcEliece460896>;
export declare function createClassicMcEliece460896f(): Promise<ClassicMcEliece460896f>;
export declare function createClassicMcEliece6688128(): Promise<ClassicMcEliece6688128>;
export declare function createClassicMcEliece6688128f(): Promise<ClassicMcEliece6688128f>;
export declare function createClassicMcEliece6960119(): Promise<ClassicMcEliece6960119>;
export declare function createClassicMcEliece6960119f(): Promise<ClassicMcEliece6960119f>;
export declare function createClassicMcEliece8192128(): Promise<ClassicMcEliece8192128>;
export declare function createClassicMcEliece8192128f(): Promise<ClassicMcEliece8192128f>;

export declare function createNTRUHps2048509(): Promise<NTRUHps2048509>;
export declare function createNTRUHps2048677(): Promise<NTRUHps2048677>;
export declare function createNTRUHps4096821(): Promise<NTRUHps4096821>;
export declare function createNTRUHps40961229(): Promise<NTRUHps40961229>;
export declare function createNTRUHrss701(): Promise<NTRUHrss701>;
export declare function createNTRUHrss1373(): Promise<NTRUHrss1373>;
export declare function createSntrup761(): Promise<Sntrup761>;

export declare function createMLDSA44(): Promise<MLDSA44>;
export declare function createMLDSA65(): Promise<MLDSA65>;
export declare function createMLDSA87(): Promise<MLDSA87>;

export declare function createFalcon512(): Promise<Falcon512>;
export declare function createFalcon1024(): Promise<Falcon1024>;
export declare function createFalconPadded512(): Promise<FalconPadded512>;
export declare function createFalconPadded1024(): Promise<FalconPadded1024>;

export declare function createMAYO1(): Promise<MAYO1>;
export declare function createMAYO2(): Promise<MAYO2>;
export declare function createMAYO3(): Promise<MAYO3>;
export declare function createMAYO5(): Promise<MAYO5>;

export declare function createOVIp(): Promise<OVIp>;
export declare function createOVIpPkc(): Promise<OVIpPkc>;
export declare function createOVIpPkcSkc(): Promise<OVIpPkcSkc>;
export declare function createOVIs(): Promise<OVIs>;
export declare function createOVIsPkc(): Promise<OVIsPkc>;
export declare function createOVIsPkcSkc(): Promise<OVIsPkcSkc>;
export declare function createOVIII(): Promise<OVIII>;
export declare function createOVIIIPkc(): Promise<OVIIIPkc>;
export declare function createOVIIIPkcSkc(): Promise<OVIIIPkcSkc>;
export declare function createOVV(): Promise<OVV>;
export declare function createOVVPkc(): Promise<OVVPkc>;
export declare function createOVVPkcSkc(): Promise<OVVPkcSkc>;

export declare function createCrossRsdp128Balanced(): Promise<CrossRsdp128Balanced>;
export declare function createCrossRsdp128Fast(): Promise<CrossRsdp128Fast>;
export declare function createCrossRsdp128Small(): Promise<CrossRsdp128Small>;
export declare function createCrossRsdp192Balanced(): Promise<CrossRsdp192Balanced>;
export declare function createCrossRsdp192Fast(): Promise<CrossRsdp192Fast>;
export declare function createCrossRsdp192Small(): Promise<CrossRsdp192Small>;
export declare function createCrossRsdp256Balanced(): Promise<CrossRsdp256Balanced>;
export declare function createCrossRsdp256Fast(): Promise<CrossRsdp256Fast>;
export declare function createCrossRsdp256Small(): Promise<CrossRsdp256Small>;
export declare function createCrossRsdpg128Balanced(): Promise<CrossRsdpg128Balanced>;
export declare function createCrossRsdpg128Fast(): Promise<CrossRsdpg128Fast>;
export declare function createCrossRsdpg128Small(): Promise<CrossRsdpg128Small>;
export declare function createCrossRsdpg192Balanced(): Promise<CrossRsdpg192Balanced>;
export declare function createCrossRsdpg192Fast(): Promise<CrossRsdpg192Fast>;
export declare function createCrossRsdpg192Small(): Promise<CrossRsdpg192Small>;
export declare function createCrossRsdpg256Balanced(): Promise<CrossRsdpg256Balanced>;
export declare function createCrossRsdpg256Fast(): Promise<CrossRsdpg256Fast>;
export declare function createCrossRsdpg256Small(): Promise<CrossRsdpg256Small>;

export declare function createSlhDsaSha2128f(): Promise<SlhDsaSha2128f>;
export declare function createSlhDsaSha2128s(): Promise<SlhDsaSha2128s>;
export declare function createSlhDsaSha2192f(): Promise<SlhDsaSha2192f>;
export declare function createSlhDsaSha2192s(): Promise<SlhDsaSha2192s>;
export declare function createSlhDsaSha2256f(): Promise<SlhDsaSha2256f>;
export declare function createSlhDsaSha2256s(): Promise<SlhDsaSha2256s>;
export declare function createSlhDsaShake128f(): Promise<SlhDsaShake128f>;
export declare function createSlhDsaShake128s(): Promise<SlhDsaShake128s>;
export declare function createSlhDsaShake192f(): Promise<SlhDsaShake192f>;
export declare function createSlhDsaShake192s(): Promise<SlhDsaShake192s>;
export declare function createSlhDsaShake256f(): Promise<SlhDsaShake256f>;
export declare function createSlhDsaShake256s(): Promise<SlhDsaShake256s>;

export declare function createSnova2454(): Promise<Snova2454>;
export declare function createSnova2454Esk(): Promise<Snova2454Esk>;
export declare function createSnova2454Shake(): Promise<Snova2454Shake>;
export declare function createSnova2454ShakeEsk(): Promise<Snova2454ShakeEsk>;
export declare function createSnova2455(): Promise<Snova2455>;
export declare function createSnova2583(): Promise<Snova2583>;
export declare function createSnova2965(): Promise<Snova2965>;
export declare function createSnova37172(): Promise<Snova37172>;
export declare function createSnova3784(): Promise<Snova3784>;
export declare function createSnova49113(): Promise<Snova49113>;
export declare function createSnova56252(): Promise<Snova56252>;
export declare function createSnova60104(): Promise<Snova60104>;

// Algorithm info constants
export declare const ML_KEM_512_INFO: Readonly<AlgorithmInfo>;
export declare const ML_KEM_768_INFO: Readonly<AlgorithmInfo>;
export declare const ML_KEM_1024_INFO: Readonly<AlgorithmInfo>;

export declare const KYBER512_INFO: Readonly<AlgorithmInfo>;
export declare const KYBER768_INFO: Readonly<AlgorithmInfo>;
export declare const KYBER1024_INFO: Readonly<AlgorithmInfo>;

export declare const FRODOKEM_640_AES_INFO: Readonly<AlgorithmInfo>;
export declare const FRODOKEM_640_SHAKE_INFO: Readonly<AlgorithmInfo>;
export declare const FRODOKEM_976_AES_INFO: Readonly<AlgorithmInfo>;
export declare const FRODOKEM_976_SHAKE_INFO: Readonly<AlgorithmInfo>;
export declare const FRODOKEM_1344_AES_INFO: Readonly<AlgorithmInfo>;
export declare const FRODOKEM_1344_SHAKE_INFO: Readonly<AlgorithmInfo>;

export declare const EFRODOKEM_640_AES_INFO: Readonly<AlgorithmInfo>;
export declare const EFRODOKEM_640_SHAKE_INFO: Readonly<AlgorithmInfo>;
export declare const EFRODOKEM_976_AES_INFO: Readonly<AlgorithmInfo>;
export declare const EFRODOKEM_976_SHAKE_INFO: Readonly<AlgorithmInfo>;
export declare const EFRODOKEM_1344_AES_INFO: Readonly<AlgorithmInfo>;
export declare const EFRODOKEM_1344_SHAKE_INFO: Readonly<AlgorithmInfo>;

export declare const HQC_128_INFO: Readonly<AlgorithmInfo>;
export declare const HQC_192_INFO: Readonly<AlgorithmInfo>;
export declare const HQC_256_INFO: Readonly<AlgorithmInfo>;

export declare const CLASSIC_MCELIECE_348864_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_348864F_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_460896_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_460896F_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_6688128_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_6688128F_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_6960119_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_6960119F_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_8192128_INFO: Readonly<AlgorithmInfo>;
export declare const CLASSIC_MCELIECE_8192128F_INFO: Readonly<AlgorithmInfo>;

export declare const NTRU_HPS_2048_509_INFO: Readonly<AlgorithmInfo>;
export declare const NTRU_HPS_2048_677_INFO: Readonly<AlgorithmInfo>;
export declare const NTRU_HPS_4096_821_INFO: Readonly<AlgorithmInfo>;
export declare const NTRU_HPS_4096_1229_INFO: Readonly<AlgorithmInfo>;
export declare const NTRU_HRSS_701_INFO: Readonly<AlgorithmInfo>;
export declare const NTRU_HRSS_1373_INFO: Readonly<AlgorithmInfo>;
export declare const SNTRUP761_INFO: Readonly<AlgorithmInfo>;

export declare const ML_DSA_44_INFO: Readonly<AlgorithmInfo>;
export declare const ML_DSA_65_INFO: Readonly<AlgorithmInfo>;
export declare const ML_DSA_87_INFO: Readonly<AlgorithmInfo>;

export declare const FALCON_512_INFO: Readonly<AlgorithmInfo>;
export declare const FALCON_1024_INFO: Readonly<AlgorithmInfo>;
export declare const FALCON_PADDED_512_INFO: Readonly<AlgorithmInfo>;
export declare const FALCON_PADDED_1024_INFO: Readonly<AlgorithmInfo>;

export declare const MAYO_1_INFO: Readonly<AlgorithmInfo>;
export declare const MAYO_2_INFO: Readonly<AlgorithmInfo>;
export declare const MAYO_3_INFO: Readonly<AlgorithmInfo>;
export declare const MAYO_5_INFO: Readonly<AlgorithmInfo>;

export declare const OV_IP_INFO: Readonly<AlgorithmInfo>;
export declare const OV_IP_PKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_IP_PKC_SKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_IS_INFO: Readonly<AlgorithmInfo>;
export declare const OV_IS_PKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_IS_PKC_SKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_III_INFO: Readonly<AlgorithmInfo>;
export declare const OV_III_PKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_III_PKC_SKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_V_INFO: Readonly<AlgorithmInfo>;
export declare const OV_V_PKC_INFO: Readonly<AlgorithmInfo>;
export declare const OV_V_PKC_SKC_INFO: Readonly<AlgorithmInfo>;

export declare const CROSS_RSDP_128_BALANCED_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_128_FAST_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_128_SMALL_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_192_BALANCED_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_192_FAST_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_192_SMALL_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_256_BALANCED_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_256_FAST_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDP_256_SMALL_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_128_BALANCED_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_128_FAST_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_128_SMALL_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_192_BALANCED_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_192_FAST_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_192_SMALL_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_256_BALANCED_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_256_FAST_INFO: Readonly<AlgorithmInfo>;
export declare const CROSS_RSDPG_256_SMALL_INFO: Readonly<AlgorithmInfo>;

export declare const SLH_DSA_SHA2_128F_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHA2_128S_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHA2_192F_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHA2_192S_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHA2_256F_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHA2_256S_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHAKE_128F_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHAKE_128S_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHAKE_192F_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHAKE_192S_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHAKE_256F_INFO: Readonly<AlgorithmInfo>;
export declare const SLH_DSA_SHAKE_256S_INFO: Readonly<AlgorithmInfo>;

export declare const SNOVA_24_5_4_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_24_5_4_ESK_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_24_5_4_SHAKE_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_24_5_4_SHAKE_ESK_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_24_5_5_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_25_8_3_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_29_6_5_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_37_17_2_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_37_8_4_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_49_11_3_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_56_25_2_INFO: Readonly<AlgorithmInfo>;
export declare const SNOVA_60_10_4_INFO: Readonly<AlgorithmInfo>;