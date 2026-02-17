/**
 * @fileoverview KEM (Key Encapsulation Mechanism) algorithm exports
 * @description Shorthand exports for all KEM algorithms
 * @module @oqs/liboqs-js/kem
 */

// Export all ML-KEM algorithms (NIST FIPS 203 standardized)
export { createMLKEM512, MLKEM512, ML_KEM_512_INFO } from './algorithms/kem/ml-kem/ml-kem-512.js';
export { createMLKEM768, MLKEM768, ML_KEM_768_INFO } from './algorithms/kem/ml-kem/ml-kem-768.js';
export { createMLKEM1024, MLKEM1024, ML_KEM_1024_INFO } from './algorithms/kem/ml-kem/ml-kem-1024.js';

// Export all Kyber algorithms (deprecated - use ML-KEM instead)
export { createKyber512, Kyber512, KYBER512_INFO } from './algorithms/kem/kyber/kyber-512.js';
export { createKyber768, Kyber768, KYBER768_INFO } from './algorithms/kem/kyber/kyber-768.js';
export { createKyber1024, Kyber1024, KYBER1024_INFO } from './algorithms/kem/kyber/kyber-1024.js';

// Export all FrodoKEM algorithms
export { createFrodoKEM640AES, FrodoKEM640AES, FRODOKEM_640_AES_INFO } from './algorithms/kem/frodokem/frodokem-640-aes.js';
export { createFrodoKEM640SHAKE, FrodoKEM640SHAKE, FRODOKEM_640_SHAKE_INFO } from './algorithms/kem/frodokem/frodokem-640-shake.js';
export { createFrodoKEM976AES, FrodoKEM976AES, FRODOKEM_976_AES_INFO } from './algorithms/kem/frodokem/frodokem-976-aes.js';
export { createFrodoKEM976SHAKE, FrodoKEM976SHAKE, FRODOKEM_976_SHAKE_INFO } from './algorithms/kem/frodokem/frodokem-976-shake.js';
export { createFrodoKEM1344AES, FrodoKEM1344AES, FRODOKEM_1344_AES_INFO } from './algorithms/kem/frodokem/frodokem-1344-aes.js';
export { createFrodoKEM1344SHAKE, FrodoKEM1344SHAKE, FRODOKEM_1344_SHAKE_INFO } from './algorithms/kem/frodokem/frodokem-1344-shake.js';

// Export all eFrodoKEM algorithms
export { createEFrodoKEM640AES, EFrodoKEM640AES, EFRODOKEM_640_AES_INFO } from './algorithms/kem/frodokem/efrodokem-640-aes.js';
export { createEFrodoKEM640SHAKE, EFrodoKEM640SHAKE, EFRODOKEM_640_SHAKE_INFO } from './algorithms/kem/frodokem/efrodokem-640-shake.js';
export { createEFrodoKEM976AES, EFrodoKEM976AES, EFRODOKEM_976_AES_INFO } from './algorithms/kem/frodokem/efrodokem-976-aes.js';
export { createEFrodoKEM976SHAKE, EFrodoKEM976SHAKE, EFRODOKEM_976_SHAKE_INFO } from './algorithms/kem/frodokem/efrodokem-976-shake.js';
export { createEFrodoKEM1344AES, EFrodoKEM1344AES, EFRODOKEM_1344_AES_INFO } from './algorithms/kem/frodokem/efrodokem-1344-aes.js';
export { createEFrodoKEM1344SHAKE, EFrodoKEM1344SHAKE, EFRODOKEM_1344_SHAKE_INFO } from './algorithms/kem/frodokem/efrodokem-1344-shake.js';

// Export all HQC algorithms
export { createHQC128, HQC128, HQC_128_INFO } from './algorithms/kem/hqc/hqc-128.js';
export { createHQC192, HQC192, HQC_192_INFO } from './algorithms/kem/hqc/hqc-192.js';
export { createHQC256, HQC256, HQC_256_INFO } from './algorithms/kem/hqc/hqc-256.js';

// Export all Classic McEliece algorithms
export { createClassicMcEliece348864, ClassicMcEliece348864, CLASSIC_MCELIECE_348864_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-348864.js';
export { createClassicMcEliece348864f, ClassicMcEliece348864f, CLASSIC_MCELIECE_348864F_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-348864f.js';
export { createClassicMcEliece460896, ClassicMcEliece460896, CLASSIC_MCELIECE_460896_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-460896.js';
export { createClassicMcEliece460896f, ClassicMcEliece460896f, CLASSIC_MCELIECE_460896F_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-460896f.js';
export { createClassicMcEliece6688128, ClassicMcEliece6688128, CLASSIC_MCELIECE_6688128_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-6688128.js';
export { createClassicMcEliece6688128f, ClassicMcEliece6688128f, CLASSIC_MCELIECE_6688128F_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-6688128f.js';
export { createClassicMcEliece6960119, ClassicMcEliece6960119, CLASSIC_MCELIECE_6960119_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-6960119.js';
export { createClassicMcEliece6960119f, ClassicMcEliece6960119f, CLASSIC_MCELIECE_6960119F_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-6960119f.js';
export { createClassicMcEliece8192128, ClassicMcEliece8192128, CLASSIC_MCELIECE_8192128_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-8192128.js';
export { createClassicMcEliece8192128f, ClassicMcEliece8192128f, CLASSIC_MCELIECE_8192128F_INFO } from './algorithms/kem/classic-mceliece/classic-mceliece-8192128f.js';

// Export all NTRU algorithms
export { createNTRUHps2048509, NTRUHps2048509, NTRU_HPS_2048_509_INFO } from './algorithms/kem/ntru/ntru-hps-2048-509.js';
export { createNTRUHps2048677, NTRUHps2048677, NTRU_HPS_2048_677_INFO } from './algorithms/kem/ntru/ntru-hps-2048-677.js';
export { createNTRUHps4096821, NTRUHps4096821, NTRU_HPS_4096_821_INFO } from './algorithms/kem/ntru/ntru-hps-4096-821.js';
export { createNTRUHps40961229, NTRUHps40961229, NTRU_HPS_4096_1229_INFO } from './algorithms/kem/ntru/ntru-hps-4096-1229.js';
export { createNTRUHrss701, NTRUHrss701, NTRU_HRSS_701_INFO } from './algorithms/kem/ntru/ntru-hrss-701.js';
export { createNTRUHrss1373, NTRUHrss1373, NTRU_HRSS_1373_INFO } from './algorithms/kem/ntru/ntru-hrss-1373.js';
export { createSntrup761, Sntrup761, SNTRUP761_INFO } from './algorithms/kem/ntru/sntrup761.js';

// Re-export error classes for convenience
export * from './core/errors.js';
