/**
 * @fileoverview NTRU-HRSS-701 KEM algorithm implementation
 * @module algorithms/kem/ntru/ntru-hrss-701
 * @description
 * NTRU-HRSS-701 is a lattice-based key encapsulation mechanism from the NTRU-HRSS (Highest Robustness Secure) family.
 * It provides post-quantum security based on the NTRU problem.
 *
 * Key features:
 * - Lattice-based cryptography (NTRU problem)
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - Enhanced robustness against side-channel attacks
 * - Compact ciphertext (1138 bytes)
 *
 * @see {@link https://ntru.org/} - NTRU specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/ntru-hrss-701.deno.js`
    : `../../../../dist/ntru-hrss-701.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * NTRU-HRSS-701-INFO algorithm constants and metadata
 * @type {{readonly name: 'NTRU-HRSS-701', readonly identifier: 'NTRU-HRSS-701', readonly type: 'kem', readonly securityLevel: 3, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 1138, readonly secretKey: 1450, readonly ciphertext: 1138, readonly sharedSecret: 32}}}
 */
export const NTRU_HRSS_701_INFO = {
  name: 'NTRU-HRSS-701',
  identifier: 'NTRU-HRSS-701',
  type: 'kem',
  securityLevel: 3,
  standardized: false,
  description: 'NTRU-HRSS-701 NTRU-HRSS (Highest Robustness Secure) (NIST Level 3, 192-bit quantum security)',
  keySize: {
    publicKey: 1138,
    secretKey: 1450,
    ciphertext: 1138,
    sharedSecret: 32
  }
};

/**
 * Factory function to create a NTRU-HRSS-701 KEM instance
 *
 * @async
 * @function createNTRUHrss701
 * @returns {Promise<NTRUHrss701>} Initialized NTRU-HRSS-701 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createNTRUHrss701 } from '@oqs/liboqs-js';
 *
 * const kem = await createNTRUHrss701();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createNTRUHrss701() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = NTRU_HRSS_701_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('NTRU-HRSS-701', 'Failed to create KEM instance');
  }

  return new NTRUHrss701(wasmModule, kemPtr);
}

/**
 * NTRU-HRSS-701 key encapsulation mechanism wrapper class
 *
 * @class NTRUHrss701
 * @description
 * High-level wrapper for NTRU-HRSS-701 KEM operations. Provides secure key generation,
 * encapsulation, and decapsulation with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const kem = await createNTRUHrss701();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = kem.generateKeyPair();
 *
 * // Encapsulate
 * const { ciphertext, sharedSecret: senderSecret } = kem.encapsulate(publicKey);
 *
 * // Decapsulate
 * const receiverSecret = kem.decapsulate(ciphertext, secretKey);
 *
 * // Cleanup
 * kem.destroy();
 */
export class NTRUHrss701 {
  /** @type {Object} @private */ #wasmModule;
  /** @type {number} @private */ #kemPtr;
  /** @type {boolean} @private */ #destroyed = false;

  /**
   * @private
   * @constructor
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} kemPtr - Pointer to OQS_KEM structure
   */
  constructor(wasmModule, kemPtr) {
    this.#wasmModule = wasmModule;
    this.#kemPtr = kemPtr;
  }

  /**
   * Generate a new NTRU-HRSS-701 keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 1138 bytes
   * console.log('Secret key:', secretKey.length);  // 1450 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(NTRU_HRSS_701_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(NTRU_HRSS_701_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'NTRU-HRSS-701', 'Key generation failed');
      }

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + publicKey.length));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + secretKey.length));

      return { publicKey, secretKey };
    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Encapsulate a shared secret using the public key
   *
   * @async
   * @param {Uint8Array} publicKey - Public key for encapsulation (1138 bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @returns {Uint8Array} returns.sharedSecret - Shared secret Ciphertext and shared secret
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   *
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
   * console.log('Ciphertext:', ciphertext.length);     // 1138 bytes
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const ciphertext = new Uint8Array(NTRU_HRSS_701_INFO.keySize.ciphertext);
    const sharedSecret = new Uint8Array(NTRU_HRSS_701_INFO.keySize.sharedSecret);

    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);
    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encapsulate', 'NTRU-HRSS-701', 'Encapsulation failed');
      }

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + ciphertext.length));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

      return { ciphertext, sharedSecret };
    } finally {
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(sharedSecretPtr);
      this.#wasmModule._free(publicKeyPtr);
    }
  }

  /**
   * Decapsulate a shared secret using the secret key
   *
   * @async
   * @param {Uint8Array} ciphertext - Ciphertext to decapsulate (1138 bytes)
   * @param {Uint8Array} secretKey - Secret key for decapsulation (1450 bytes)
   * @returns {Uint8Array} Shared secret (32 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   *
   * @example
   * const sharedSecret = kem.decapsulate(ciphertext, secretKey);
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const sharedSecret = new Uint8Array(NTRU_HRSS_701_INFO.keySize.sharedSecret);

    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);
    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      this.#wasmModule.HEAPU8.set(ciphertext, ciphertextPtr);
      this.#wasmModule.HEAPU8.set(secretKey, secretKeyPtr);

      const result = this.#wasmModule._OQS_KEM_decaps(
        this.#kemPtr,
        sharedSecretPtr,
        ciphertextPtr,
        secretKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('decapsulate', 'NTRU-HRSS-701', 'Decapsulation failed');
      }

      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

      return sharedSecret;
    } finally {
      this.#wasmModule._free(sharedSecretPtr);
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Free WASM resources
   *
   * @description
   * Releases all WASM memory associated with this instance.
   * The instance cannot be used after calling destroy().
   *
   * @example
   * kem.destroy();
   * // kem is now unusable
   */
  destroy() {
    if (!this.#destroyed && this.#kemPtr) {
      this.#wasmModule._OQS_KEM_free(this.#kemPtr);
      this.#kemPtr = null;
      this.#destroyed = true;
    }
  }

  /**
   * Enables automatic cleanup via `using` declarations
   * @example
   * using instance = await create...();
   * // automatically cleaned up at end of scope
   */
  [Symbol.dispose]() {
    this.destroy();
  }

  /**
   * Get algorithm information
   *
   * @readonly
   * @returns {typeof NTRU_HRSS_701_INFO} Algorithm metadata
   *
   * @example
   * console.log(kem.info.name);           // 'NTRU-HRSS-701'
   * console.log(kem.info.securityLevel);  // 3
   * console.log(kem.info.keySize);        // { publicKey: 1138, secretKey: 1450, ciphertext: 1138, sharedSecret: 32 }
   */
  get info() {
    return NTRU_HRSS_701_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'NTRU-HRSS-701');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== NTRU_HRSS_701_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${NTRU_HRSS_701_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'NTRU-HRSS-701'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== NTRU_HRSS_701_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${NTRU_HRSS_701_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'NTRU-HRSS-701'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} ciphertext
   * @throws {LibOQSValidationError} If ciphertext size is invalid
   */
  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== NTRU_HRSS_701_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${NTRU_HRSS_701_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'NTRU-HRSS-701'
      );
    }
  }
}
