/**
 * @fileoverview Kyber512 KEM algorithm implementation (DEPRECATED)
 * @module algorithms/kem/kyber/kyber-512
 * @description
 * Kyber512 is a lattice-based key encapsulation mechanism providing NIST security level 1.
 *
 * **DEPRECATED:** Kyber has been superseded by ML-KEM (NIST FIPS 203). Use ML-KEM-512 instead.
 *
 * Key features:
 * - Lattice-based cryptography (Module-LWE problem)
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - IND-CCA2 security
 * - Smallest key sizes in Kyber family
 *
 * @see {@link https://pq-crystals.org/kyber/} - Kyber specification
 * @deprecated Use ML-KEM-512 instead (NIST FIPS 203 standardized version)
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/kyber-512.deno.js`
    : `../../../../dist/kyber-512.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * KYBER512-INFO algorithm constants and metadata
 * @type {{readonly name: 'Kyber512', readonly identifier: 'Kyber512', readonly type: 'kem', readonly securityLevel: 1, readonly standardized: false, readonly deprecated: true, readonly description: string, readonly keySize: {readonly publicKey: 800, readonly secretKey: 1632, readonly ciphertext: 768, readonly sharedSecret: 32}}}
 */
export const KYBER512_INFO = {
  name: 'Kyber512',
  identifier: 'Kyber512',
  type: 'kem',
  securityLevel: 1,
  standardized: false,
  deprecated: true,
  description: 'Kyber512 (128-bit quantum security) - DEPRECATED, use ML-KEM-512',
  keySize: {
    publicKey: 800,
    secretKey: 1632,
    ciphertext: 768,
    sharedSecret: 32
  }
};

/**
 * Factory function to create an Kyber512 KEM instance
 *
 * @async
 * @function createKyber512
 * @returns {Promise<Kyber512>} Initialized Kyber512 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createKyber512 } from '@oqs/liboqs-js';
 *
 * const kem = await createKyber512();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createKyber512() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = KYBER512_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('Kyber512', 'Failed to create KEM instance');
  }

  return new Kyber512(wasmModule, kemPtr);
}

/**
 * Kyber512 wrapper class providing high-level KEM operations
 *
 * This class wraps the low-level WASM module to provide a user-friendly
 * interface for Kyber512 operations with automatic memory management
 * and input validation.
 *
 * @class Kyber512
 * @example
 * import LibOQS_ml_kem_512 from '@oqs/liboqs-js/kyber-512';
 * import { createKyber512 } from '@oqs/liboqs-js/algorithms/kyber-512';
 *
 * const kem = await createKyber512(LibOQS_ml_kem_512);
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
 * kem.destroy();
 */
export class Kyber512 {
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
   * Generate a new keypair for Kyber512
   *
   * Generates a public/private keypair using the algorithm's internal
   * random number generator. The secret key must be kept confidential.
   *
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSOperationError} If keypair generation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * // publicKey: 800 bytes
   * // secretKey: 1632 bytes (keep confidential!)
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKeyPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('keypair', 'Kyber512', `Error code: ${result}`);
      }

      const publicKey = new Uint8Array(KYBER512_INFO.keySize.publicKey);
      const secretKey = new Uint8Array(KYBER512_INFO.keySize.secretKey);

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + KYBER512_INFO.keySize.publicKey));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + KYBER512_INFO.keySize.secretKey));

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
   * @param {Uint8Array} publicKey - Recipient's public key (800 bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   * @throws {LibOQSError} If instance has been destroyed
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(recipientPublicKey);
   * // ciphertext: 768 bytes (send to recipient)
   * // sharedSecret: 32 bytes (use for symmetric encryption)
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const publicKeyPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.publicKey);
    const ciphertextPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.ciphertext);
    const sharedSecretPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.sharedSecret);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encaps', 'Kyber512', `Error code: ${result}`);
      }

      const ciphertext = new Uint8Array(KYBER512_INFO.keySize.ciphertext);
      const sharedSecret = new Uint8Array(KYBER512_INFO.keySize.sharedSecret);

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + KYBER512_INFO.keySize.ciphertext));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + KYBER512_INFO.keySize.sharedSecret));

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
   * @param {Uint8Array} ciphertext - Ciphertext received (768 bytes)
   * @param {Uint8Array} secretKey - Recipient's secret key (1632 bytes)
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

    const ciphertextPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.ciphertext);
    const secretKeyPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.secretKey);
    const sharedSecretPtr = this.#wasmModule._malloc(KYBER512_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('decaps', 'Kyber512', `Error code: ${result}`);
      }

      const sharedSecret = new Uint8Array(KYBER512_INFO.keySize.sharedSecret);
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + KYBER512_INFO.keySize.sharedSecret));

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
   * const kem = await createKyber512(LibOQS_ml_kem_512);
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
   * @returns {typeof KYBER512_INFO} Algorithm metadata (copy of KYBER512_INFO)
   * @example
   * const info = kem.info;
   * console.log(info.keySize.publicKey); // 800
   */
  get info() {
    return KYBER512_INFO;
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'Kyber512');
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== KYBER512_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${KYBER512_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'Kyber512'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== KYBER512_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${KYBER512_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'Kyber512'
      );
    }
  }

  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== KYBER512_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${KYBER512_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'Kyber512'
      );
    }
  }
}

