/**
 * @fileoverview Kyber768 KEM algorithm implementation (DEPRECATED)
 * @module algorithms/kem/kyber/kyber-768
 * @description
 * Kyber768 is a lattice-based key encapsulation mechanism providing NIST security level 3.
 *
 * **DEPRECATED:** Kyber has been superseded by ML-KEM (NIST FIPS 203). Use ML-KEM-768 instead.
 * It is part of the standard (Module-Lattice-Based Key-Encapsulation Mechanism).
 *
 * Key features:
 * - Lattice-based cryptography (Module-LWE problem)
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - IND-CCA2 security
 * - IND-CCA2 security
 * - Efficient key sizes and performance
 *
 * @see {@link https://pq-crystals.org/kyber/} - Kyber specification
 * @deprecated Use ML-KEM-768 instead (NIST FIPS 203 standardized version
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/kyber-768.deno.js`
    : `../../../../dist/kyber-768.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * KYBER768-INFO algorithm constants and metadata
 * @type {{readonly name: 'Kyber768', readonly identifier: 'Kyber768', readonly type: 'kem', readonly securityLevel: 3, readonly standardized: false, readonly deprecated: true, readonly description: string, readonly keySize: {readonly publicKey: 1184, readonly secretKey: 2400, readonly ciphertext: 1088, readonly sharedSecret: 32}}}
 */
export const KYBER768_INFO = {
  name: 'Kyber768',
  identifier: 'Kyber768',
  type: 'kem',
  securityLevel: 3,
  standardized: false,
  deprecated: true,
  description: 'Kyber768 (192-bit quantum security) - DEPRECATED, use ML-KEM-768',
  keySize: {
    publicKey: 1184,
    secretKey: 2400,
    ciphertext: 1088,
    sharedSecret: 32
  }
};

/**
 * Factory function to create an Kyber768 KEM instance
 *
 * @async
 * @function createKyber768
 * @returns {Promise<Kyber768>} Initialized Kyber768 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createKyber768 } from '@oqs/liboqs-js';
 *
 * const kem = await createKyber768();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createKyber768() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = KYBER768_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('Kyber768', 'Failed to create KEM instance');
  }

  return new Kyber768(wasmModule, kemPtr);
}

/**
 * Kyber768 wrapper class providing high-level KEM operations
 *
 * This class wraps the low-level WASM module to provide a user-friendly
 * interface for Kyber768 operations with automatic memory management
 * and input validation.
 *
 * @class Kyber768
 * @example
 * import { createKyber768 } from '@oqs/liboqs-js';
 *
 * const kem = await createKyber768();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
 * kem.destroy();
 */
export class Kyber768 {
  /** @type {Object} @private */
  #wasmModule;
  /** @type {number} @private */
  #kemPtr;
  /** @type {boolean} @private */
  #destroyed = false;

  /**
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} kemPtr - Pointer to KEM instance
   * @private
   */
  constructor(wasmModule, kemPtr) {
    this.#wasmModule = wasmModule;
    this.#kemPtr = kemPtr;
  }

  /**
   * Generate a new keypair for Kyber768
   *
   * Generates a public/private keypair using the algorithm's internal
   * random number generator. The secret key must be kept confidential.
   *
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSOperationError} If keypair generation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * // publicKey: 1184 bytes
   * // secretKey: 2400 bytes (keep confidential!)
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKeyPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('keypair', 'Kyber768', `Error code: ${result}`);
      }

      const publicKey = new Uint8Array(KYBER768_INFO.keySize.publicKey);
      const secretKey = new Uint8Array(KYBER768_INFO.keySize.secretKey);

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + KYBER768_INFO.keySize.publicKey));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + KYBER768_INFO.keySize.secretKey));

      return { publicKey, secretKey };

    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Encapsulate a shared secret using a public key
   *
   * Generates a random shared secret and encapsulates it using the
   * provided public key. The shared secret can be used for symmetric
   * encryption.
   *
   * @param {Uint8Array} publicKey - Recipient's public key (1184 bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(recipientPublicKey);
   * // ciphertext: 1088 bytes (send to recipient)
   * // sharedSecret: 32 bytes (use for symmetric encryption)
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const publicKeyPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.publicKey);
    const ciphertextPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.ciphertext);
    const sharedSecretPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.sharedSecret);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encaps', 'Kyber768', `Error code: ${result}`);
      }

      const ciphertext = new Uint8Array(KYBER768_INFO.keySize.ciphertext);
      const sharedSecret = new Uint8Array(KYBER768_INFO.keySize.sharedSecret);

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + KYBER768_INFO.keySize.ciphertext));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + KYBER768_INFO.keySize.sharedSecret));

      return { ciphertext, sharedSecret };

    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(sharedSecretPtr);
    }
  }

  /**
   * Decapsulate a shared secret using a secret key
   *
   * Recovers the shared secret from a ciphertext using the secret key.
   * The recovered shared secret will match the one generated during
   * encapsulation.
   *
   * @param {Uint8Array} ciphertext - Ciphertext received (1088 bytes)
   * @param {Uint8Array} secretKey - Recipient's secret key (2400 bytes)
   * @returns {Uint8Array} Recovered shared secret (32 bytes)
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const sharedSecret = kem.decapsulate(ciphertext, mySecretKey);
   * // sharedSecret: 32 bytes (matches sender's shared secret)
   */
  decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const ciphertextPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.ciphertext);
    const secretKeyPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.secretKey);
    const sharedSecretPtr = this.#wasmModule._malloc(KYBER768_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('decaps', 'Kyber768', `Error code: ${result}`);
      }

      const sharedSecret = new Uint8Array(KYBER768_INFO.keySize.sharedSecret);
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + KYBER768_INFO.keySize.sharedSecret));

      return sharedSecret;

    } finally {
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(sharedSecretPtr);
    }
  }

  /**
   * Clean up resources and free WASM memory
   *
   * This method should be called when you're done using the instance
   * to free WASM memory. After calling destroy(), the instance cannot
   * be used for further operations.
   *
   * @example
   * const kem = await createKyber768(LibOQS_ml_kem_768);
   * // ... use kem ...
   * kem.destroy();
   */
  destroy() {
    if (!this.#destroyed) {
      if (this.#kemPtr) {
        this.#wasmModule._OQS_KEM_free(this.#kemPtr);
        this.#kemPtr = null;
      }
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
   * Get algorithm information and constants
   * @returns {typeof KYBER768_INFO} Algorithm metadata (copy of KYBER768_INFO)
   * @example
   * const info = kem.info;
   * console.log(info.keySize.publicKey); // 1184
   */
  get info() {
    return KYBER768_INFO;
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'Kyber768');
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== KYBER768_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${KYBER768_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'Kyber768'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== KYBER768_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${KYBER768_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'Kyber768'
      );
    }
  }

  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== KYBER768_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${KYBER768_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'Kyber768'
      );
    }
  }
}

