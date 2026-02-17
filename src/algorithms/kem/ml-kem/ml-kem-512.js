/**
 * @fileoverview ML-KEM-512 KEM algorithm implementation
 * @module algorithms/kem/ml-kem/ml-kem-512
 * @description
 * ML-KEM-512 is a lattice-based key encapsulation mechanism providing NIST security level 1.
 * It is part of the NIST FIPS 203 standard (Module-Lattice-Based Key-Encapsulation Mechanism).
 *
 * Key features:
 * - Lattice-based cryptography (Module-LWE problem)
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - NIST FIPS 203 standardized
 * - IND-CCA2 security
 * - Smallest key sizes in ML-KEM family
 *
 * @see {@link https://csrc.nist.gov/pubs/fips/203/final} - NIST FIPS 203 specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/ml-kem-512.deno.js`
    : `../../../../dist/ml-kem-512.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * ML-KEM-512 algorithm constants and metadata
 * @constant {Readonly<{name: 'ML-KEM-512', identifier: 'ML-KEM-512', type: 'kem', securityLevel: 1, standardized: true, description: string, keySize: {publicKey: 800, secretKey: 1632, ciphertext: 768, sharedSecret: 32}}>} ML_KEM_512_INFO
 */
export const ML_KEM_512_INFO = /** @type {const} */ ({
  name: 'ML-KEM-512',
  identifier: 'ML-KEM-512',
  type: 'kem',
  securityLevel: 1,
  standardized: true,
  description: 'NIST FIPS 203 ML-KEM-512 (128-bit quantum security)',
  keySize: {
    publicKey: 800,
    secretKey: 1632,
    ciphertext: 768,
    sharedSecret: 32
  }
});

/**
 * Factory function to create an ML-KEM-512 KEM instance
 *
 * @async
 * @function createMLKEM512
 * @returns {Promise<MLKEM512>} Initialized ML-KEM-512 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createMLKEM512 } from '@oqs/liboqs-js';
 *
 * const kem = await createMLKEM512();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createMLKEM512() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = ML_KEM_512_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('ML-KEM-512', 'Failed to create KEM instance');
  }

  return new MLKEM512(wasmModule, kemPtr);
}

/**
 * ML-KEM-512 wrapper class providing high-level KEM operations
 *
 * This class wraps the low-level WASM module to provide a user-friendly
 * interface for ML-KEM-512 operations with automatic memory management
 * and input validation.
 *
 * @class MLKEM512
 * @example
 * import LibOQS_ml_kem_512 from '@oqs/liboqs-js/ml-kem-512';
 * import { createMLKEM512 } from '@oqs/liboqs-js/algorithms/ml-kem-512';
 *
 * const kem = await createMLKEM512(LibOQS_ml_kem_512);
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
 * kem.destroy();
 */
export class MLKEM512 {
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
   * Generate a new keypair for ML-KEM-512
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

    const publicKeyPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('keypair', 'ML-KEM-512', `Error code: ${result}`);
      }

      const publicKey = new Uint8Array(ML_KEM_512_INFO.keySize.publicKey);
      const secretKey = new Uint8Array(ML_KEM_512_INFO.keySize.secretKey);

      publicKey.set(this.#wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + ML_KEM_512_INFO.keySize.publicKey));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(secretKeyPtr, secretKeyPtr + ML_KEM_512_INFO.keySize.secretKey));

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

    const publicKeyPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.publicKey);
    const ciphertextPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.ciphertext);
    const sharedSecretPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.sharedSecret);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encaps', 'ML-KEM-512', `Error code: ${result}`);
      }

      const ciphertext = new Uint8Array(ML_KEM_512_INFO.keySize.ciphertext);
      const sharedSecret = new Uint8Array(ML_KEM_512_INFO.keySize.sharedSecret);

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + ML_KEM_512_INFO.keySize.ciphertext));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + ML_KEM_512_INFO.keySize.sharedSecret));

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

    const ciphertextPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.ciphertext);
    const secretKeyPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.secretKey);
    const sharedSecretPtr = this.#wasmModule._malloc(ML_KEM_512_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('decaps', 'ML-KEM-512', `Error code: ${result}`);
      }

      const sharedSecret = new Uint8Array(ML_KEM_512_INFO.keySize.sharedSecret);
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + ML_KEM_512_INFO.keySize.sharedSecret));

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
   * const kem = await createMLKEM512(LibOQS_ml_kem_512);
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
   * @returns {typeof ML_KEM_512_INFO} Algorithm metadata
   * @example
   * const info = kem.info;
   * console.log(info.keySize.publicKey); // 800
   */
  get info() {
    return ML_KEM_512_INFO;
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'ML-KEM-512');
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== ML_KEM_512_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${ML_KEM_512_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'ML-KEM-512'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== ML_KEM_512_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${ML_KEM_512_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'ML-KEM-512'
      );
    }
  }

  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== ML_KEM_512_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${ML_KEM_512_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'ML-KEM-512'
      );
    }
  }
}

