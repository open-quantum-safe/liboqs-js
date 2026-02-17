/**
 * @fileoverview Signature algorithm exports
 * @description Shorthand exports for all signature algorithms
 * @module @oqs/liboqs-js/sig
 */

// Export all ML-DSA algorithms
export { createMLDSA44, MLDSA44, ML_DSA_44_INFO } from './algorithms/sig/ml-dsa/ml-dsa-44.js';
export { createMLDSA65, MLDSA65, ML_DSA_65_INFO } from './algorithms/sig/ml-dsa/ml-dsa-65.js';
export { createMLDSA87, MLDSA87, ML_DSA_87_INFO } from './algorithms/sig/ml-dsa/ml-dsa-87.js';

// Export all Falcon algorithms
export { createFalcon512, Falcon512, FALCON_512_INFO } from './algorithms/sig/falcon/falcon-512.js';
export { createFalcon1024, Falcon1024, FALCON_1024_INFO } from './algorithms/sig/falcon/falcon-1024.js';
export { createFalconPadded512, FalconPadded512, FALCON_PADDED_512_INFO } from './algorithms/sig/falcon/falcon-padded-512.js';
export { createFalconPadded1024, FalconPadded1024, FALCON_PADDED_1024_INFO } from './algorithms/sig/falcon/falcon-padded-1024.js';

// Export all MAYO algorithms
export { createMAYO1, MAYO1, MAYO_1_INFO } from './algorithms/sig/mayo/mayo-1.js';
export { createMAYO2, MAYO2, MAYO_2_INFO } from './algorithms/sig/mayo/mayo-2.js';
export { createMAYO3, MAYO3, MAYO_3_INFO } from './algorithms/sig/mayo/mayo-3.js';
export { createMAYO5, MAYO5, MAYO_5_INFO } from './algorithms/sig/mayo/mayo-5.js';

// Export all UOV algorithms
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

// Export all CROSS algorithms
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

// Export all SLH-DSA algorithms
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

// Export all SNOVA algorithms
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

// Re-export error classes for convenience
export * from './core/errors.js';
