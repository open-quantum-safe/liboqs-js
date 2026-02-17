/**
 * @fileoverview Algorithm factory lookup
 */

import * as allExports from '../index.js';

// Map of algorithm slugs to factory function names
const KEM_ALGORITHMS = {
  'ml-kem-512': 'createMLKEM512',
  'ml-kem-768': 'createMLKEM768',
  'ml-kem-1024': 'createMLKEM1024',
  'kyber512': 'createKyber512',
  'kyber768': 'createKyber768',
  'kyber1024': 'createKyber1024',
  'frodokem-640-aes': 'createFrodoKEM640AES',
  'frodokem-640-shake': 'createFrodoKEM640SHAKE',
  'frodokem-976-aes': 'createFrodoKEM976AES',
  'frodokem-976-shake': 'createFrodoKEM976SHAKE',
  'frodokem-1344-aes': 'createFrodoKEM1344AES',
  'frodokem-1344-shake': 'createFrodoKEM1344SHAKE',
  'hqc-128': 'createHQC128',
  'hqc-192': 'createHQC192',
  'hqc-256': 'createHQC256',
  'classic-mceliece-348864': 'createClassicMcEliece348864',
  'classic-mceliece-348864f': 'createClassicMcEliece348864f',
  'classic-mceliece-460896': 'createClassicMcEliece460896',
  'classic-mceliece-460896f': 'createClassicMcEliece460896f',
  'classic-mceliece-6688128': 'createClassicMcEliece6688128',
  'classic-mceliece-6688128f': 'createClassicMcEliece6688128f',
  'classic-mceliece-6960119': 'createClassicMcEliece6960119',
  'classic-mceliece-6960119f': 'createClassicMcEliece6960119f',
  'classic-mceliece-8192128': 'createClassicMcEliece8192128',
  'classic-mceliece-8192128f': 'createClassicMcEliece8192128f',
  'ntru-hps-2048-509': 'createNTRUHps2048509',
  'ntru-hps-2048-677': 'createNTRUHps2048677',
  'ntru-hps-4096-821': 'createNTRUHps4096821',
  'ntru-hps-4096-1229': 'createNTRUHps40961229',
  'ntru-hrss-701': 'createNTRUHrss701',
  'ntru-hrss-1373': 'createNTRUHrss1373',
  'sntrup761': 'createSntrup761'
};

const SIG_ALGORITHMS = {
  'ml-dsa-44': 'createMLDSA44',
  'ml-dsa-65': 'createMLDSA65',
  'ml-dsa-87': 'createMLDSA87',
  'falcon-512': 'createFalcon512',
  'falcon-1024': 'createFalcon1024',
  'falcon-padded-512': 'createFalconPadded512',
  'falcon-padded-1024': 'createFalconPadded1024',
  'mayo-1': 'createMAYO1',
  'mayo-2': 'createMAYO2',
  'mayo-3': 'createMAYO3',
  'mayo-5': 'createMAYO5',
  'ov-ip': 'createOVIp',
  'ov-ip-pkc': 'createOVIpPkc',
  'ov-ip-pkc-skc': 'createOVIpPkcSkc',
  'ov-is': 'createOVIs',
  'ov-is-pkc': 'createOVIsPkc',
  'ov-is-pkc-skc': 'createOVIsPkcSkc',
  'ov-iii': 'createOVIII',
  'ov-iii-pkc': 'createOVIIIPkc',
  'ov-iii-pkc-skc': 'createOVIIIPkcSkc',
  'ov-v': 'createOVV',
  'ov-v-pkc': 'createOVVPkc',
  'ov-v-pkc-skc': 'createOVVPkcSkc',
  'cross-rsdp-128-balanced': 'createCrossRsdp128Balanced',
  'cross-rsdp-128-fast': 'createCrossRsdp128Fast',
  'cross-rsdp-128-small': 'createCrossRsdp128Small',
  'cross-rsdp-192-balanced': 'createCrossRsdp192Balanced',
  'cross-rsdp-192-fast': 'createCrossRsdp192Fast',
  'cross-rsdp-192-small': 'createCrossRsdp192Small',
  'cross-rsdp-256-balanced': 'createCrossRsdp256Balanced',
  'cross-rsdp-256-fast': 'createCrossRsdp256Fast',
  'cross-rsdp-256-small': 'createCrossRsdp256Small',
  'cross-rsdpg-128-balanced': 'createCrossRsdpg128Balanced',
  'cross-rsdpg-128-fast': 'createCrossRsdpg128Fast',
  'cross-rsdpg-128-small': 'createCrossRsdpg128Small',
  'cross-rsdpg-192-balanced': 'createCrossRsdpg192Balanced',
  'cross-rsdpg-192-fast': 'createCrossRsdpg192Fast',
  'cross-rsdpg-192-small': 'createCrossRsdpg192Small',
  'cross-rsdpg-256-balanced': 'createCrossRsdpg256Balanced',
  'cross-rsdpg-256-fast': 'createCrossRsdpg256Fast',
  'cross-rsdpg-256-small': 'createCrossRsdpg256Small',
  'slh-dsa-sha2-128f': 'createSlhDsaSha2128f',
  'slh-dsa-sha2-128s': 'createSlhDsaSha2128s',
  'slh-dsa-sha2-192f': 'createSlhDsaSha2192f',
  'slh-dsa-sha2-192s': 'createSlhDsaSha2192s',
  'slh-dsa-sha2-256f': 'createSlhDsaSha2256f',
  'slh-dsa-sha2-256s': 'createSlhDsaSha2256s',
  'slh-dsa-shake-128f': 'createSlhDsaShake128f',
  'slh-dsa-shake-128s': 'createSlhDsaShake128s',
  'slh-dsa-shake-192f': 'createSlhDsaShake192f',
  'slh-dsa-shake-192s': 'createSlhDsaShake192s',
  'slh-dsa-shake-256f': 'createSlhDsaShake256f',
  'slh-dsa-shake-256s': 'createSlhDsaShake256s',
  'snova-24-5-4': 'createSnova2454',
  'snova-24-5-4-esk': 'createSnova2454Esk',
  'snova-24-5-4-shake': 'createSnova2454Shake',
  'snova-24-5-4-shake-esk': 'createSnova2454ShakeEsk',
  'snova-24-5-5': 'createSnova2455',
  'snova-25-8-3': 'createSnova2583',
  'snova-29-6-5': 'createSnova2965',
  'snova-37-17-2': 'createSnova37172',
  'snova-37-8-4': 'createSnova3784',
  'snova-49-11-3': 'createSnova49113',
  'snova-56-25-2': 'createSnova56252',
  'snova-60-10-4': 'createSnova60104'
};

export function getKemFactory(algorithm) {
  const slug = algorithm.toLowerCase();
  const factoryName = KEM_ALGORITHMS[slug];

  if (!factoryName) {
    throw new Error(`Unknown KEM algorithm: ${algorithm}\nRun 'liboqs list --kem' to see available algorithms`);
  }

  return allExports[factoryName];
}

export function getSigFactory(algorithm) {
  const slug = algorithm.toLowerCase();
  const factoryName = SIG_ALGORITHMS[slug];

  if (!factoryName) {
    throw new Error(`Unknown signature algorithm: ${algorithm}\nRun 'liboqs list --sig' to see available algorithms`);
  }

  return allExports[factoryName];
}

// Map factory names to INFO constant names
const INFO_MAP = {
  'createMLKEM512': 'ML_KEM_512_INFO',
  'createMLKEM768': 'ML_KEM_768_INFO',
  'createMLKEM1024': 'ML_KEM_1024_INFO',
  'createKyber512': 'KYBER512_INFO',
  'createKyber768': 'KYBER768_INFO',
  'createKyber1024': 'KYBER1024_INFO',
  'createFrodoKEM640AES': 'FRODOKEM_640_AES_INFO',
  'createFrodoKEM640SHAKE': 'FRODOKEM_640_SHAKE_INFO',
  'createFrodoKEM976AES': 'FRODOKEM_976_AES_INFO',
  'createFrodoKEM976SHAKE': 'FRODOKEM_976_SHAKE_INFO',
  'createFrodoKEM1344AES': 'FRODOKEM_1344_AES_INFO',
  'createFrodoKEM1344SHAKE': 'FRODOKEM_1344_SHAKE_INFO',
  'createHQC128': 'HQC_128_INFO',
  'createHQC192': 'HQC_192_INFO',
  'createHQC256': 'HQC_256_INFO',
  'createClassicMcEliece348864': 'CLASSIC_MCELIECE_348864_INFO',
  'createClassicMcEliece348864f': 'CLASSIC_MCELIECE_348864F_INFO',
  'createClassicMcEliece460896': 'CLASSIC_MCELIECE_460896_INFO',
  'createClassicMcEliece460896f': 'CLASSIC_MCELIECE_460896F_INFO',
  'createClassicMcEliece6688128': 'CLASSIC_MCELIECE_6688128_INFO',
  'createClassicMcEliece6688128f': 'CLASSIC_MCELIECE_6688128F_INFO',
  'createClassicMcEliece6960119': 'CLASSIC_MCELIECE_6960119_INFO',
  'createClassicMcEliece6960119f': 'CLASSIC_MCELIECE_6960119F_INFO',
  'createClassicMcEliece8192128': 'CLASSIC_MCELIECE_8192128_INFO',
  'createClassicMcEliece8192128f': 'CLASSIC_MCELIECE_8192128F_INFO',
  'createNTRUHps2048509': 'NTRU_HPS_2048_509_INFO',
  'createNTRUHps2048677': 'NTRU_HPS_2048_677_INFO',
  'createNTRUHps4096821': 'NTRU_HPS_4096_821_INFO',
  'createNTRUHps40961229': 'NTRU_HPS_4096_1229_INFO',
  'createNTRUHrss701': 'NTRU_HRSS_701_INFO',
  'createNTRUHrss1373': 'NTRU_HRSS_1373_INFO',
  'createSntrup761': 'SNTRUP761_INFO',
  'createMLDSA44': 'ML_DSA_44_INFO',
  'createMLDSA65': 'ML_DSA_65_INFO',
  'createMLDSA87': 'ML_DSA_87_INFO',
  'createFalcon512': 'FALCON_512_INFO',
  'createFalcon1024': 'FALCON_1024_INFO',
  'createFalconPadded512': 'FALCON_PADDED_512_INFO',
  'createFalconPadded1024': 'FALCON_PADDED_1024_INFO',
  'createMAYO1': 'MAYO_1_INFO',
  'createMAYO2': 'MAYO_2_INFO',
  'createMAYO3': 'MAYO_3_INFO',
  'createMAYO5': 'MAYO_5_INFO',
  'createOVIp': 'OV_IP_INFO',
  'createOVIpPkc': 'OV_IP_PKC_INFO',
  'createOVIpPkcSkc': 'OV_IP_PKC_SKC_INFO',
  'createOVIs': 'OV_IS_INFO',
  'createOVIsPkc': 'OV_IS_PKC_INFO',
  'createOVIsPkcSkc': 'OV_IS_PKC_SKC_INFO',
  'createOVIII': 'OV_III_INFO',
  'createOVIIIPkc': 'OV_III_PKC_INFO',
  'createOVIIIPkcSkc': 'OV_III_PKC_SKC_INFO',
  'createOVV': 'OV_V_INFO',
  'createOVVPkc': 'OV_V_PKC_INFO',
  'createOVVPkcSkc': 'OV_V_PKC_SKC_INFO',
  'createCrossRsdp128Balanced': 'CROSS_RSDP_128_BALANCED_INFO',
  'createCrossRsdp128Fast': 'CROSS_RSDP_128_FAST_INFO',
  'createCrossRsdp128Small': 'CROSS_RSDP_128_SMALL_INFO',
  'createCrossRsdp192Balanced': 'CROSS_RSDP_192_BALANCED_INFO',
  'createCrossRsdp192Fast': 'CROSS_RSDP_192_FAST_INFO',
  'createCrossRsdp192Small': 'CROSS_RSDP_192_SMALL_INFO',
  'createCrossRsdp256Balanced': 'CROSS_RSDP_256_BALANCED_INFO',
  'createCrossRsdp256Fast': 'CROSS_RSDP_256_FAST_INFO',
  'createCrossRsdp256Small': 'CROSS_RSDP_256_SMALL_INFO',
  'createCrossRsdpg128Balanced': 'CROSS_RSDPG_128_BALANCED_INFO',
  'createCrossRsdpg128Fast': 'CROSS_RSDPG_128_FAST_INFO',
  'createCrossRsdpg128Small': 'CROSS_RSDPG_128_SMALL_INFO',
  'createCrossRsdpg192Balanced': 'CROSS_RSDPG_192_BALANCED_INFO',
  'createCrossRsdpg192Fast': 'CROSS_RSDPG_192_FAST_INFO',
  'createCrossRsdpg192Small': 'CROSS_RSDPG_192_SMALL_INFO',
  'createCrossRsdpg256Balanced': 'CROSS_RSDPG_256_BALANCED_INFO',
  'createCrossRsdpg256Fast': 'CROSS_RSDPG_256_FAST_INFO',
  'createCrossRsdpg256Small': 'CROSS_RSDPG_256_SMALL_INFO',
  'createSlhDsaSha2128f': 'SLH_DSA_SHA2_128F_INFO',
  'createSlhDsaSha2128s': 'SLH_DSA_SHA2_128S_INFO',
  'createSlhDsaSha2192f': 'SLH_DSA_SHA2_192F_INFO',
  'createSlhDsaSha2192s': 'SLH_DSA_SHA2_192S_INFO',
  'createSlhDsaSha2256f': 'SLH_DSA_SHA2_256F_INFO',
  'createSlhDsaSha2256s': 'SLH_DSA_SHA2_256S_INFO',
  'createSlhDsaShake128f': 'SLH_DSA_SHAKE_128F_INFO',
  'createSlhDsaShake128s': 'SLH_DSA_SHAKE_128S_INFO',
  'createSlhDsaShake192f': 'SLH_DSA_SHAKE_192F_INFO',
  'createSlhDsaShake192s': 'SLH_DSA_SHAKE_192S_INFO',
  'createSlhDsaShake256f': 'SLH_DSA_SHAKE_256F_INFO',
  'createSlhDsaShake256s': 'SLH_DSA_SHAKE_256S_INFO',
  'createSnova2454': 'SNOVA_24_5_4_INFO',
  'createSnova2454Esk': 'SNOVA_24_5_4_ESK_INFO',
  'createSnova2454Shake': 'SNOVA_24_5_4_SHAKE_INFO',
  'createSnova2454ShakeEsk': 'SNOVA_24_5_4_SHAKE_ESK_INFO',
  'createSnova2455': 'SNOVA_24_5_5_INFO',
  'createSnova2583': 'SNOVA_25_8_3_INFO',
  'createSnova2965': 'SNOVA_29_6_5_INFO',
  'createSnova37172': 'SNOVA_37_17_2_INFO',
  'createSnova3784': 'SNOVA_37_8_4_INFO',
  'createSnova49113': 'SNOVA_49_11_3_INFO',
  'createSnova56252': 'SNOVA_56_25_2_INFO',
  'createSnova60104': 'SNOVA_60_10_4_INFO'
};

export function getAlgorithmInfo(algorithm) {
  const slug = algorithm.toLowerCase();

  // Try KEM first
  const kemFactory = KEM_ALGORITHMS[slug];
  if (kemFactory) {
    const infoName = INFO_MAP[kemFactory];
    return allExports[infoName];
  }

  // Try SIG
  const sigFactory = SIG_ALGORITHMS[slug];
  if (sigFactory) {
    const infoName = INFO_MAP[sigFactory];
    return allExports[infoName];
  }

  throw new Error(`Unknown algorithm: ${algorithm}`);
}

export { KEM_ALGORITHMS, SIG_ALGORITHMS };
