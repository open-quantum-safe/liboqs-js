/**
 * @fileoverview Main entry point for @oqs/liboqs-js
 * @description Post-quantum cryptography for Node.js and browsers via WebAssembly bindings to liboqs
 *
 * @example
 * // Key encapsulation (ML-KEM)
 * import { createMLKEM768 } from '@oqs/liboqs-js';
 *
 * const kem = await createMLKEM768();
 * const { publicKey, secretKey } = await kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
 * kem.destroy();
 *
 * @example
 * // Digital signatures (ML-DSA)
 * import { createMLDSA65 } from '@oqs/liboqs-js';
 *
 * const sig = await createMLDSA65();
 * const { publicKey, secretKey } = await sig.generateKeyPair();
 * const message = new TextEncoder().encode('Hello!');
 * const signature = await sig.sign(message, secretKey);
 * const isValid = await sig.verify(message, signature, publicKey);
 * sig.destroy();
 */

// Re-export error classes
export * from './core/errors.js';

// Export ML-KEM algorithms (NIST FIPS 203 standardized)
export { createMLKEM512, MLKEM512, ML_KEM_512_INFO } from './algorithms/kem/ml-kem/ml-kem-512.js';
export { createMLKEM768, MLKEM768, ML_KEM_768_INFO } from './algorithms/kem/ml-kem/ml-kem-768.js';
export { createMLKEM1024, MLKEM1024, ML_KEM_1024_INFO } from './algorithms/kem/ml-kem/ml-kem-1024.js';

// Export Kyber algorithms (deprecated - use ML-KEM instead)
export { createKyber512, Kyber512, KYBER512_INFO } from './algorithms/kem/kyber/kyber-512.js';
export { createKyber768, Kyber768, KYBER768_INFO } from './algorithms/kem/kyber/kyber-768.js';
export { createKyber1024, Kyber1024, KYBER1024_INFO } from './algorithms/kem/kyber/kyber-1024.js';

// Export ML-DSA signature algorithms
export { createMLDSA44, MLDSA44, ML_DSA_44_INFO } from './algorithms/sig/ml-dsa/ml-dsa-44.js';
export { createMLDSA65, MLDSA65, ML_DSA_65_INFO } from './algorithms/sig/ml-dsa/ml-dsa-65.js';
export { createMLDSA87, MLDSA87, ML_DSA_87_INFO } from './algorithms/sig/ml-dsa/ml-dsa-87.js';

// Export Falcon signature algorithms
export { createFalcon512, Falcon512, FALCON_512_INFO } from './algorithms/sig/falcon/falcon-512.js';
export { createFalcon1024, Falcon1024, FALCON_1024_INFO } from './algorithms/sig/falcon/falcon-1024.js';
export { createFalconPadded512, FalconPadded512, FALCON_PADDED_512_INFO } from './algorithms/sig/falcon/falcon-padded-512.js';
export { createFalconPadded1024, FalconPadded1024, FALCON_PADDED_1024_INFO } from './algorithms/sig/falcon/falcon-padded-1024.js';

// Export MAYO signature algorithms
export { createMAYO1, MAYO1, MAYO_1_INFO } from './algorithms/sig/mayo/mayo-1.js';
export { createMAYO2, MAYO2, MAYO_2_INFO } from './algorithms/sig/mayo/mayo-2.js';
export { createMAYO3, MAYO3, MAYO_3_INFO } from './algorithms/sig/mayo/mayo-3.js';
export { createMAYO5, MAYO5, MAYO_5_INFO } from './algorithms/sig/mayo/mayo-5.js';

// Export UOV signature algorithms
export { createOVIp, OVIp, OV_IP_INFO } from './algorithms/sig/uov/ov-ip.js';
export { createOVIpPkc, OVIpPkc, OV_IP_PKC_INFO } from './algorithms/sig/uov/ov-ip-pkc.js';
export { createOVIpPkcSkc, OVIpPkcSkc, OV_IP_PKC_SKC_INFO } from './algorithms/sig/uov/ov-ip-pkc-skc.js';
export { createOVIs, OVIs, OV_IS_INFO } from './algorithms/sig/uov/ov-is.js';
export { createOVIsPkc, OVIsPkc, OV_IS_PKC_INFO } from './algorithms/sig/uov/ov-is-pkc.js';
export { createOVIsPkcSkc, OVIsPkcSkc, OV_IS_PKC_SKC_INFO } from './algorithms/sig/uov/ov-is-pkc-skc.js';
export { createOVIII, OVIII, OV_III_INFO } from './algorithms/sig/uov/ov-iii.js';
export { createOVIIIPkc, OVIIIPkc, OV_III_PKC_INFO } from './algorithms/sig/uov/ov-iii-pkc.js';
export { createOVIIIPkcSkc, OVIIIPkcSkc, OV_III_PKC_SKC_INFO } from './algorithms/sig/uov/ov-iii-pkc-skc.js';
export { createOVV, OVV, OV_V_INFO } from './algorithms/sig/uov/ov-v.js';
export { createOVVPkc, OVVPkc, OV_V_PKC_INFO } from './algorithms/sig/uov/ov-v-pkc.js';
export { createOVVPkcSkc, OVVPkcSkc, OV_V_PKC_SKC_INFO } from './algorithms/sig/uov/ov-v-pkc-skc.js';

// Export Classic McEliece KEM algorithms
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

// Export FrodoKEM KEM algorithms
export { createFrodoKEM640AES, FrodoKEM640AES, FRODOKEM_640_AES_INFO } from './algorithms/kem/frodokem/frodokem-640-aes.js';
export { createFrodoKEM640SHAKE, FrodoKEM640SHAKE, FRODOKEM_640_SHAKE_INFO } from './algorithms/kem/frodokem/frodokem-640-shake.js';
export { createFrodoKEM976AES, FrodoKEM976AES, FRODOKEM_976_AES_INFO } from './algorithms/kem/frodokem/frodokem-976-aes.js';
export { createFrodoKEM976SHAKE, FrodoKEM976SHAKE, FRODOKEM_976_SHAKE_INFO } from './algorithms/kem/frodokem/frodokem-976-shake.js';
export { createFrodoKEM1344AES, FrodoKEM1344AES, FRODOKEM_1344_AES_INFO } from './algorithms/kem/frodokem/frodokem-1344-aes.js';
export { createFrodoKEM1344SHAKE, FrodoKEM1344SHAKE, FRODOKEM_1344_SHAKE_INFO } from './algorithms/kem/frodokem/frodokem-1344-shake.js';

// Export eFrodoKEM KEM algorithms
export { createEFrodoKEM640AES, EFrodoKEM640AES, EFRODOKEM_640_AES_INFO } from './algorithms/kem/frodokem/efrodokem-640-aes.js';
export { createEFrodoKEM640SHAKE, EFrodoKEM640SHAKE, EFRODOKEM_640_SHAKE_INFO } from './algorithms/kem/frodokem/efrodokem-640-shake.js';
export { createEFrodoKEM976AES, EFrodoKEM976AES, EFRODOKEM_976_AES_INFO } from './algorithms/kem/frodokem/efrodokem-976-aes.js';
export { createEFrodoKEM976SHAKE, EFrodoKEM976SHAKE, EFRODOKEM_976_SHAKE_INFO } from './algorithms/kem/frodokem/efrodokem-976-shake.js';
export { createEFrodoKEM1344AES, EFrodoKEM1344AES, EFRODOKEM_1344_AES_INFO } from './algorithms/kem/frodokem/efrodokem-1344-aes.js';
export { createEFrodoKEM1344SHAKE, EFrodoKEM1344SHAKE, EFRODOKEM_1344_SHAKE_INFO } from './algorithms/kem/frodokem/efrodokem-1344-shake.js';

// Export HQC KEM algorithms
export { createHQC128, HQC128, HQC_128_INFO } from './algorithms/kem/hqc/hqc-128.js';
export { createHQC192, HQC192, HQC_192_INFO } from './algorithms/kem/hqc/hqc-192.js';
export { createHQC256, HQC256, HQC_256_INFO } from './algorithms/kem/hqc/hqc-256.js';

// Export NTRU KEM algorithms
export { createNTRUHps2048509, NTRUHps2048509, NTRU_HPS_2048_509_INFO } from './algorithms/kem/ntru/ntru-hps-2048-509.js';
export { createNTRUHps2048677, NTRUHps2048677, NTRU_HPS_2048_677_INFO } from './algorithms/kem/ntru/ntru-hps-2048-677.js';
export { createNTRUHps4096821, NTRUHps4096821, NTRU_HPS_4096_821_INFO } from './algorithms/kem/ntru/ntru-hps-4096-821.js';
export { createNTRUHps40961229, NTRUHps40961229, NTRU_HPS_4096_1229_INFO } from './algorithms/kem/ntru/ntru-hps-4096-1229.js';
export { createNTRUHrss701, NTRUHrss701, NTRU_HRSS_701_INFO } from './algorithms/kem/ntru/ntru-hrss-701.js';
export { createNTRUHrss1373, NTRUHrss1373, NTRU_HRSS_1373_INFO } from './algorithms/kem/ntru/ntru-hrss-1373.js';
export { createSntrup761, Sntrup761, SNTRUP761_INFO } from './algorithms/kem/ntru/sntrup761.js';

// Export CROSS signature algorithms
export { createCrossRsdp128Balanced, CrossRsdp128Balanced, CROSS_RSDP_128_BALANCED_INFO } from './algorithms/sig/cross/cross-rsdp-128-balanced.js';
export { createCrossRsdp128Fast, CrossRsdp128Fast, CROSS_RSDP_128_FAST_INFO } from './algorithms/sig/cross/cross-rsdp-128-fast.js';
export { createCrossRsdp128Small, CrossRsdp128Small, CROSS_RSDP_128_SMALL_INFO } from './algorithms/sig/cross/cross-rsdp-128-small.js';
export { createCrossRsdp192Balanced, CrossRsdp192Balanced, CROSS_RSDP_192_BALANCED_INFO } from './algorithms/sig/cross/cross-rsdp-192-balanced.js';
export { createCrossRsdp192Fast, CrossRsdp192Fast, CROSS_RSDP_192_FAST_INFO } from './algorithms/sig/cross/cross-rsdp-192-fast.js';
export { createCrossRsdp192Small, CrossRsdp192Small, CROSS_RSDP_192_SMALL_INFO } from './algorithms/sig/cross/cross-rsdp-192-small.js';
export { createCrossRsdp256Balanced, CrossRsdp256Balanced, CROSS_RSDP_256_BALANCED_INFO } from './algorithms/sig/cross/cross-rsdp-256-balanced.js';
export { createCrossRsdp256Fast, CrossRsdp256Fast, CROSS_RSDP_256_FAST_INFO } from './algorithms/sig/cross/cross-rsdp-256-fast.js';
export { createCrossRsdp256Small, CrossRsdp256Small, CROSS_RSDP_256_SMALL_INFO } from './algorithms/sig/cross/cross-rsdp-256-small.js';
export { createCrossRsdpg128Balanced, CrossRsdpg128Balanced, CROSS_RSDPG_128_BALANCED_INFO } from './algorithms/sig/cross/cross-rsdpg-128-balanced.js';
export { createCrossRsdpg128Fast, CrossRsdpg128Fast, CROSS_RSDPG_128_FAST_INFO } from './algorithms/sig/cross/cross-rsdpg-128-fast.js';
export { createCrossRsdpg128Small, CrossRsdpg128Small, CROSS_RSDPG_128_SMALL_INFO } from './algorithms/sig/cross/cross-rsdpg-128-small.js';
export { createCrossRsdpg192Balanced, CrossRsdpg192Balanced, CROSS_RSDPG_192_BALANCED_INFO } from './algorithms/sig/cross/cross-rsdpg-192-balanced.js';
export { createCrossRsdpg192Fast, CrossRsdpg192Fast, CROSS_RSDPG_192_FAST_INFO } from './algorithms/sig/cross/cross-rsdpg-192-fast.js';
export { createCrossRsdpg192Small, CrossRsdpg192Small, CROSS_RSDPG_192_SMALL_INFO } from './algorithms/sig/cross/cross-rsdpg-192-small.js';
export { createCrossRsdpg256Balanced, CrossRsdpg256Balanced, CROSS_RSDPG_256_BALANCED_INFO } from './algorithms/sig/cross/cross-rsdpg-256-balanced.js';
export { createCrossRsdpg256Fast, CrossRsdpg256Fast, CROSS_RSDPG_256_FAST_INFO } from './algorithms/sig/cross/cross-rsdpg-256-fast.js';
export { createCrossRsdpg256Small, CrossRsdpg256Small, CROSS_RSDPG_256_SMALL_INFO } from './algorithms/sig/cross/cross-rsdpg-256-small.js';

// Export all SLH-DSA algorithms (FIPS 205 standardized)
export { createSlhDsaSha2128f, SlhDsaSha2128f, SLH_DSA_SHA2_128F_INFO } from './algorithms/sig/slh-dsa/slh-dsa-sha2-128f.js';
export { createSlhDsaSha2128s, SlhDsaSha2128s, SLH_DSA_SHA2_128S_INFO } from './algorithms/sig/slh-dsa/slh-dsa-sha2-128s.js';
export { createSlhDsaSha2192f, SlhDsaSha2192f, SLH_DSA_SHA2_192F_INFO } from './algorithms/sig/slh-dsa/slh-dsa-sha2-192f.js';
export { createSlhDsaSha2192s, SlhDsaSha2192s, SLH_DSA_SHA2_192S_INFO } from './algorithms/sig/slh-dsa/slh-dsa-sha2-192s.js';
export { createSlhDsaSha2256f, SlhDsaSha2256f, SLH_DSA_SHA2_256F_INFO } from './algorithms/sig/slh-dsa/slh-dsa-sha2-256f.js';
export { createSlhDsaSha2256s, SlhDsaSha2256s, SLH_DSA_SHA2_256S_INFO } from './algorithms/sig/slh-dsa/slh-dsa-sha2-256s.js';
export { createSlhDsaShake128f, SlhDsaShake128f, SLH_DSA_SHAKE_128F_INFO } from './algorithms/sig/slh-dsa/slh-dsa-shake-128f.js';
export { createSlhDsaShake128s, SlhDsaShake128s, SLH_DSA_SHAKE_128S_INFO } from './algorithms/sig/slh-dsa/slh-dsa-shake-128s.js';
export { createSlhDsaShake192f, SlhDsaShake192f, SLH_DSA_SHAKE_192F_INFO } from './algorithms/sig/slh-dsa/slh-dsa-shake-192f.js';
export { createSlhDsaShake192s, SlhDsaShake192s, SLH_DSA_SHAKE_192S_INFO } from './algorithms/sig/slh-dsa/slh-dsa-shake-192s.js';
export { createSlhDsaShake256f, SlhDsaShake256f, SLH_DSA_SHAKE_256F_INFO } from './algorithms/sig/slh-dsa/slh-dsa-shake-256f.js';
export { createSlhDsaShake256s, SlhDsaShake256s, SLH_DSA_SHAKE_256S_INFO } from './algorithms/sig/slh-dsa/slh-dsa-shake-256s.js';

// Export SNOVA signature algorithms
export { createSnova2454, Snova2454, SNOVA_24_5_4_INFO } from './algorithms/sig/snova/snova-24-5-4.js';
export { createSnova2454Esk, Snova2454Esk, SNOVA_24_5_4_ESK_INFO } from './algorithms/sig/snova/snova-24-5-4-esk.js';
export { createSnova2454Shake, Snova2454Shake, SNOVA_24_5_4_SHAKE_INFO } from './algorithms/sig/snova/snova-24-5-4-shake.js';
export { createSnova2454ShakeEsk, Snova2454ShakeEsk, SNOVA_24_5_4_SHAKE_ESK_INFO } from './algorithms/sig/snova/snova-24-5-4-shake-esk.js';
export { createSnova2455, Snova2455, SNOVA_24_5_5_INFO } from './algorithms/sig/snova/snova-24-5-5.js';
export { createSnova2583, Snova2583, SNOVA_25_8_3_INFO } from './algorithms/sig/snova/snova-25-8-3.js';
export { createSnova2965, Snova2965, SNOVA_29_6_5_INFO } from './algorithms/sig/snova/snova-29-6-5.js';
export { createSnova37172, Snova37172, SNOVA_37_17_2_INFO } from './algorithms/sig/snova/snova-37-17-2.js';
export { createSnova3784, Snova3784, SNOVA_37_8_4_INFO } from './algorithms/sig/snova/snova-37-8-4.js';
export { createSnova49113, Snova49113, SNOVA_49_11_3_INFO } from './algorithms/sig/snova/snova-49-11-3.js';
export { createSnova56252, Snova56252, SNOVA_56_25_2_INFO } from './algorithms/sig/snova/snova-56-25-2.js';
export { createSnova60104, Snova60104, SNOVA_60_10_4_INFO } from './algorithms/sig/snova/snova-60-10-4.js';

/**
 * Library version
 * @constant {string}
 */
export const VERSION = '0.15.1';
