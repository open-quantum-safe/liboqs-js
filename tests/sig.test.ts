/**
 * @fileoverview Unit tests for SIG (Digital Signature) algorithms
 * @description Tests all implemented signature algorithms for basic functionality:
 * - Key pair generation
 * - Message signing
 * - Signature verification
 * - Invalid signature detection
 */

import { describe, test, expect } from 'vitest';

/**
 * Helper to compare Uint8Array values across Node.js and browser environments
 */
function compareArrays(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return 1;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return 1;
  }
  return 0;
}

import {
  createMLDSA44,
  createMLDSA65,
  createMLDSA87,
  ML_DSA_44_INFO,
  ML_DSA_65_INFO,
  ML_DSA_87_INFO,
  createFalcon512,
  createFalcon1024,
  createFalconPadded512,
  createFalconPadded1024,
  FALCON_512_INFO,
  FALCON_1024_INFO,
  FALCON_PADDED_512_INFO,
  FALCON_PADDED_1024_INFO,
  createMAYO1,
  createMAYO2,
  createMAYO3,
  createMAYO5,
  MAYO_1_INFO,
  MAYO_2_INFO,
  MAYO_3_INFO,
  MAYO_5_INFO,
  createOVIp,
  createOVIpPkc,
  createOVIpPkcSkc,
  createOVIs,
  createOVIsPkc,
  createOVIsPkcSkc,
  createOVIII,
  createOVIIIPkc,
  createOVIIIPkcSkc,
  createOVV,
  createOVVPkc,
  createOVVPkcSkc,
  OV_IP_INFO,
  OV_IP_PKC_INFO,
  OV_IP_PKC_SKC_INFO,
  OV_IS_INFO,
  OV_IS_PKC_INFO,
  OV_IS_PKC_SKC_INFO,
  OV_III_INFO,
  OV_III_PKC_INFO,
  OV_III_PKC_SKC_INFO,
  OV_V_INFO,
  OV_V_PKC_INFO,
  OV_V_PKC_SKC_INFO,
  createCrossRsdp128Balanced,
  createCrossRsdp128Fast,
  createCrossRsdp128Small,
  createCrossRsdp192Balanced,
  createCrossRsdp192Fast,
  createCrossRsdp192Small,
  createCrossRsdp256Balanced,
  createCrossRsdp256Fast,
  createCrossRsdp256Small,
  createCrossRsdpg128Balanced,
  createCrossRsdpg128Fast,
  createCrossRsdpg128Small,
  createCrossRsdpg192Balanced,
  createCrossRsdpg192Fast,
  createCrossRsdpg192Small,
  createCrossRsdpg256Balanced,
  createCrossRsdpg256Fast,
  createCrossRsdpg256Small,
  CROSS_RSDP_128_BALANCED_INFO,
  CROSS_RSDP_128_FAST_INFO,
  CROSS_RSDP_128_SMALL_INFO,
  CROSS_RSDP_192_BALANCED_INFO,
  CROSS_RSDP_192_FAST_INFO,
  CROSS_RSDP_192_SMALL_INFO,
  CROSS_RSDP_256_BALANCED_INFO,
  CROSS_RSDP_256_FAST_INFO,
  CROSS_RSDP_256_SMALL_INFO,
  CROSS_RSDPG_128_BALANCED_INFO,
  CROSS_RSDPG_128_FAST_INFO,
  CROSS_RSDPG_128_SMALL_INFO,
  CROSS_RSDPG_192_BALANCED_INFO,
  CROSS_RSDPG_192_FAST_INFO,
  CROSS_RSDPG_192_SMALL_INFO,
  CROSS_RSDPG_256_BALANCED_INFO,
  CROSS_RSDPG_256_FAST_INFO,
  CROSS_RSDPG_256_SMALL_INFO,
  createSlhDsaSha2128f,
  createSlhDsaSha2128s,
  createSlhDsaSha2192f,
  createSlhDsaSha2192s,
  createSlhDsaSha2256f,
  createSlhDsaSha2256s,
  createSlhDsaShake128f,
  createSlhDsaShake128s,
  createSlhDsaShake192f,
  createSlhDsaShake192s,
  createSlhDsaShake256f,
  createSlhDsaShake256s,
  SLH_DSA_SHA2_128F_INFO,
  SLH_DSA_SHA2_128S_INFO,
  SLH_DSA_SHA2_192F_INFO,
  SLH_DSA_SHA2_192S_INFO,
  SLH_DSA_SHA2_256F_INFO,
  SLH_DSA_SHA2_256S_INFO,
  SLH_DSA_SHAKE_128F_INFO,
  SLH_DSA_SHAKE_128S_INFO,
  SLH_DSA_SHAKE_192F_INFO,
  SLH_DSA_SHAKE_192S_INFO,
  SLH_DSA_SHAKE_256F_INFO,
  SLH_DSA_SHAKE_256S_INFO,
  createSnova2454,
  createSnova2454Esk,
  createSnova2454Shake,
  createSnova2454ShakeEsk,
  createSnova2455,
  createSnova2583,
  createSnova2965,
  createSnova37172,
  createSnova3784,
  createSnova49113,
  createSnova56252,
  createSnova60104,
  SNOVA_24_5_4_INFO,
  SNOVA_24_5_4_ESK_INFO,
  SNOVA_24_5_4_SHAKE_INFO,
  SNOVA_24_5_4_SHAKE_ESK_INFO,
  SNOVA_24_5_5_INFO,
  SNOVA_25_8_3_INFO,
  SNOVA_29_6_5_INFO,
  SNOVA_37_17_2_INFO,
  SNOVA_37_8_4_INFO,
  SNOVA_49_11_3_INFO,
  SNOVA_56_25_2_INFO,
  SNOVA_60_10_4_INFO
} from '../src/index.js';
import type { SIGInstance, AlgorithmInfo } from "../src/types/algorithms.d.ts";

// Import WASM modules

/**
 * Registry of all signature algorithms to test
 * Add new algorithms here when implemented
 */
const sigAlgorithms: Array<{
  name: string;
  factory: () => Promise<SIGInstance>;
  info: AlgorithmInfo;
}> = [
    { name: 'ML-DSA-44', factory: createMLDSA44, info: ML_DSA_44_INFO },
    { name: 'ML-DSA-65', factory: createMLDSA65, info: ML_DSA_65_INFO },
    { name: 'ML-DSA-87', factory: createMLDSA87, info: ML_DSA_87_INFO },
    { name: 'Falcon-512', factory: createFalcon512, info: FALCON_512_INFO },
    { name: 'Falcon-1024', factory: createFalcon1024, info: FALCON_1024_INFO },
    { name: 'Falcon-padded-512', factory: createFalconPadded512, info: FALCON_PADDED_512_INFO },
    { name: 'Falcon-padded-1024', factory: createFalconPadded1024, info: FALCON_PADDED_1024_INFO },
    { name: 'MAYO-1', factory: createMAYO1, info: MAYO_1_INFO },
    { name: 'MAYO-2', factory: createMAYO2, info: MAYO_2_INFO },
    { name: 'MAYO-3', factory: createMAYO3, info: MAYO_3_INFO },
    { name: 'MAYO-5', factory: createMAYO5, info: MAYO_5_INFO },
    { name: 'OV-Ip', factory: createOVIp, info: OV_IP_INFO },
    { name: 'OV-Ip-pkc', factory: createOVIpPkc, info: OV_IP_PKC_INFO },
    { name: 'OV-Ip-pkc-skc', factory: createOVIpPkcSkc, info: OV_IP_PKC_SKC_INFO },
    { name: 'OV-Is', factory: createOVIs, info: OV_IS_INFO },
    { name: 'OV-Is-pkc', factory: createOVIsPkc, info: OV_IS_PKC_INFO },
    { name: 'OV-Is-pkc-skc', factory: createOVIsPkcSkc, info: OV_IS_PKC_SKC_INFO },
    { name: 'OV-III', factory: createOVIII, info: OV_III_INFO },
    { name: 'OV-III-pkc', factory: createOVIIIPkc, info: OV_III_PKC_INFO },
    { name: 'OV-III-pkc-skc', factory: createOVIIIPkcSkc, info: OV_III_PKC_SKC_INFO },
    { name: 'OV-V', factory: createOVV, info: OV_V_INFO },
    { name: 'OV-V-pkc', factory: createOVVPkc, info: OV_V_PKC_INFO },
    { name: 'OV-V-pkc-skc', factory: createOVVPkcSkc, info: OV_V_PKC_SKC_INFO },
    { name: 'CROSS-rsdp-128-balanced', factory: createCrossRsdp128Balanced, info: CROSS_RSDP_128_BALANCED_INFO },
    { name: 'CROSS-rsdp-128-fast', factory: createCrossRsdp128Fast, info: CROSS_RSDP_128_FAST_INFO },
    { name: 'CROSS-rsdp-128-small', factory: createCrossRsdp128Small, info: CROSS_RSDP_128_SMALL_INFO },
    { name: 'CROSS-rsdp-192-balanced', factory: createCrossRsdp192Balanced, info: CROSS_RSDP_192_BALANCED_INFO },
    { name: 'CROSS-rsdp-192-fast', factory: createCrossRsdp192Fast, info: CROSS_RSDP_192_FAST_INFO },
    { name: 'CROSS-rsdp-192-small', factory: createCrossRsdp192Small, info: CROSS_RSDP_192_SMALL_INFO },
    { name: 'CROSS-rsdp-256-balanced', factory: createCrossRsdp256Balanced, info: CROSS_RSDP_256_BALANCED_INFO },
    { name: 'CROSS-rsdp-256-fast', factory: createCrossRsdp256Fast, info: CROSS_RSDP_256_FAST_INFO },
    { name: 'CROSS-rsdp-256-small', factory: createCrossRsdp256Small, info: CROSS_RSDP_256_SMALL_INFO },
    { name: 'CROSS-rsdpg-128-balanced', factory: createCrossRsdpg128Balanced, info: CROSS_RSDPG_128_BALANCED_INFO },
    { name: 'CROSS-rsdpg-128-fast', factory: createCrossRsdpg128Fast, info: CROSS_RSDPG_128_FAST_INFO },
    { name: 'CROSS-rsdpg-128-small', factory: createCrossRsdpg128Small, info: CROSS_RSDPG_128_SMALL_INFO },
    { name: 'CROSS-rsdpg-192-balanced', factory: createCrossRsdpg192Balanced, info: CROSS_RSDPG_192_BALANCED_INFO },
    { name: 'CROSS-rsdpg-192-fast', factory: createCrossRsdpg192Fast, info: CROSS_RSDPG_192_FAST_INFO },
    { name: 'CROSS-rsdpg-192-small', factory: createCrossRsdpg192Small, info: CROSS_RSDPG_192_SMALL_INFO },
    { name: 'CROSS-rsdpg-256-balanced', factory: createCrossRsdpg256Balanced, info: CROSS_RSDPG_256_BALANCED_INFO },
    { name: 'CROSS-rsdpg-256-fast', factory: createCrossRsdpg256Fast, info: CROSS_RSDPG_256_FAST_INFO },
    { name: 'CROSS-rsdpg-256-small', factory: createCrossRsdpg256Small, info: CROSS_RSDPG_256_SMALL_INFO },
    { name: 'SLH-DSA-SHA2-128f', factory: createSlhDsaSha2128f, info: SLH_DSA_SHA2_128F_INFO },
    { name: 'SLH-DSA-SHA2-128s', factory: createSlhDsaSha2128s, info: SLH_DSA_SHA2_128S_INFO },
    { name: 'SLH-DSA-SHA2-192f', factory: createSlhDsaSha2192f, info: SLH_DSA_SHA2_192F_INFO },
    { name: 'SLH-DSA-SHA2-192s', factory: createSlhDsaSha2192s, info: SLH_DSA_SHA2_192S_INFO },
    { name: 'SLH-DSA-SHA2-256f', factory: createSlhDsaSha2256f, info: SLH_DSA_SHA2_256F_INFO },
    { name: 'SLH-DSA-SHA2-256s', factory: createSlhDsaSha2256s, info: SLH_DSA_SHA2_256S_INFO },
    { name: 'SLH-DSA-SHAKE-128f', factory: createSlhDsaShake128f, info: SLH_DSA_SHAKE_128F_INFO },
    { name: 'SLH-DSA-SHAKE-128s', factory: createSlhDsaShake128s, info: SLH_DSA_SHAKE_128S_INFO },
    { name: 'SLH-DSA-SHAKE-192f', factory: createSlhDsaShake192f, info: SLH_DSA_SHAKE_192F_INFO },
    { name: 'SLH-DSA-SHAKE-192s', factory: createSlhDsaShake192s, info: SLH_DSA_SHAKE_192S_INFO },
    { name: 'SLH-DSA-SHAKE-256f', factory: createSlhDsaShake256f, info: SLH_DSA_SHAKE_256F_INFO },
    { name: 'SLH-DSA-SHAKE-256s', factory: createSlhDsaShake256s, info: SLH_DSA_SHAKE_256S_INFO },
    { name: 'SNOVA-24-5-4', factory: createSnova2454, info: SNOVA_24_5_4_INFO },
    { name: 'SNOVA-24-5-4-esk', factory: createSnova2454Esk, info: SNOVA_24_5_4_ESK_INFO },
    { name: 'SNOVA-24-5-4-SHAKE', factory: createSnova2454Shake, info: SNOVA_24_5_4_SHAKE_INFO },
    { name: 'SNOVA-24-5-4-SHAKE-esk', factory: createSnova2454ShakeEsk, info: SNOVA_24_5_4_SHAKE_ESK_INFO },
    { name: 'SNOVA-24-5-5', factory: createSnova2455, info: SNOVA_24_5_5_INFO },
    { name: 'SNOVA-25-8-3', factory: createSnova2583, info: SNOVA_25_8_3_INFO },
    { name: 'SNOVA-29-6-5', factory: createSnova2965, info: SNOVA_29_6_5_INFO },
    { name: 'SNOVA-37-17-2', factory: createSnova37172, info: SNOVA_37_17_2_INFO },
    { name: 'SNOVA-37-8-4', factory: createSnova3784, info: SNOVA_37_8_4_INFO },
    { name: 'SNOVA-49-11-3', factory: createSnova49113, info: SNOVA_49_11_3_INFO },
    { name: 'SNOVA-56-25-2', factory: createSnova56252, info: SNOVA_56_25_2_INFO },
    { name: 'SNOVA-60-10-4', factory: createSnova60104, info: SNOVA_60_10_4_INFO }
  ];

describe('Signature Algorithms', () => {
  describe.each(sigAlgorithms)('$name', ({ name, factory, info }) => {
    test('should generate valid keypair', async () => {
      const sig = await factory();

      const { publicKey, secretKey } = sig.generateKeyPair();

      expect(publicKey).toBeInstanceOf(Uint8Array);
      expect(secretKey).toBeInstanceOf(Uint8Array);
      expect(publicKey.length).toBe(info.keySize.publicKey);
      expect(secretKey.length).toBe(info.keySize.secretKey);

      sig.destroy();
    });

    test('should sign message and produce valid signature', async () => {
      const sig = await factory();
      const { secretKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test message for signing');

      const signature = sig.sign(message, secretKey);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
      if (info.keySize.signature !== undefined) {
        expect(signature.length).toBeLessThanOrEqual(info.keySize.signature);
      }

      sig.destroy();
    });

    test('should verify valid signature', async () => {
      const sig = await factory();
      const { publicKey, secretKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature = sig.sign(message, secretKey);
      const isValid = sig.verify(message, signature, publicKey);

      expect(isValid).toBe(true);

      sig.destroy();
    });

    test('should reject signature with wrong message', async () => {
      const sig = await factory();
      const { publicKey, secretKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Original message');
      const wrongMessage = new TextEncoder().encode('Wrong message');

      const signature = sig.sign(message, secretKey);
      const isValid = sig.verify(wrongMessage, signature, publicKey);

      expect(isValid).toBe(false);

      sig.destroy();
    });

    test('should reject signature with wrong public key', async () => {
      const sig = await factory();
      const keypair1 = sig.generateKeyPair();
      const keypair2 = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature = sig.sign(message, keypair1.secretKey);
      const isValid = sig.verify(message, signature, keypair2.publicKey);

      expect(isValid).toBe(false);

      sig.destroy();
    });

    test('should reject tampered signature', async () => {
      const sig = await factory();
      const { publicKey, secretKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature = sig.sign(message, secretKey);

      // Tamper with signature
      const tamperedSignature = new Uint8Array(signature);
      tamperedSignature[0] ^= 0xFF;

      const isValid = sig.verify(message, tamperedSignature, publicKey);

      expect(isValid).toBe(false);

      sig.destroy();
    });

    test('should produce different signatures on each signing', async () => {
      const sig = await factory();
      const { secretKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature1 = sig.sign(message, secretKey);
      const signature2 = sig.sign(message, secretKey);

      // ML-DSA is randomized, so signatures should differ
      expect(compareArrays(signature1, signature2)).not.toBe(0);

      sig.destroy();
    });

    test('should produce different keypairs on each generation', async () => {
      const sig = await factory();

      const keypair1 = sig.generateKeyPair();
      const keypair2 = sig.generateKeyPair();

      // Public keys should differ
      expect(compareArrays(keypair1.publicKey, keypair2.publicKey)).not.toBe(0);
      // Secret keys should differ
      expect(compareArrays(keypair1.secretKey, keypair2.secretKey)).not.toBe(0);

      sig.destroy();
    });

    test('should sign and verify empty message', async () => {
      const sig = await factory();
      const { publicKey, secretKey } = sig.generateKeyPair();
      const emptyMessage = new Uint8Array(0);

      const signature = sig.sign(emptyMessage, secretKey);
      const isValid = sig.verify(emptyMessage, signature, publicKey);

      expect(isValid).toBe(true);

      sig.destroy();
    });

    test('should sign and verify large message', async () => {
      const sig = await factory();
      const { publicKey, secretKey } = sig.generateKeyPair();
      // Create 1MB message
      const largeMessage = new Uint8Array(1024 * 1024).fill(42);

      const signature = sig.sign(largeMessage, secretKey);
      const isValid = sig.verify(largeMessage, signature, publicKey);

      expect(isValid).toBe(true);

      sig.destroy();
    });

    test('should have correct algorithm info', async () => {
      const sig = await factory();
      const sigInfo = sig.info;

      expect(sigInfo.name).toBe(name);
      expect(sigInfo.identifier).toBe(info.identifier);
      expect(sigInfo.type).toBe('sig');
      expect(sigInfo.standardized).toBe(info.standardized);
      expect(sigInfo.keySize).toEqual(info.keySize);

      sig.destroy();
    });

    test('should throw error when using destroyed instance', async () => {
      const sig = await factory();
      sig.destroy();

      expect(() => sig.generateKeyPair()).toThrow(/destroyed/);
    });

    test('should support Symbol.dispose', async () => {
      const sig = await factory();
      expect(typeof sig[Symbol.dispose]).toBe('function');
      sig[Symbol.dispose]();
      expect(() => sig.generateKeyPair()).toThrow(/destroyed/);
    });

    test('should throw error on invalid public key size', async () => {
      const sig = await factory();
      const { secretKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test');
      const signature = sig.sign(message, secretKey);
      const invalidPublicKey = new Uint8Array(10); // Wrong size

      expect(() => sig.verify(message, signature, invalidPublicKey)).toThrow(/Invalid public key/);

      sig.destroy();
    });

    test('should throw error on invalid secret key size', async () => {
      const sig = await factory();
      const message = new TextEncoder().encode('Test');
      const invalidSecretKey = new Uint8Array(10); // Wrong size

      expect(() => sig.sign(message, invalidSecretKey)).toThrow(/Invalid secret key/);

      sig.destroy();
    });

    test('should throw error on invalid signature size', async () => {
      const sig = await factory();
      const { publicKey } = sig.generateKeyPair();
      const message = new TextEncoder().encode('Test');
      const invalidSignature = new Uint8Array(0); // Empty signature

      expect(() => sig.verify(message, invalidSignature, publicKey)).toThrow(/Invalid signature/);

      sig.destroy();
    });
  });
});
