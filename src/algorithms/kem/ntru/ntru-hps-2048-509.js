/**
 * @fileoverview NTRU-HPS-2048-509 KEM algorithm implementation
 * @module algorithms/kem/ntru/ntru-hps-2048-509
 * @description
 * NTRU-HPS-2048-509 is a lattice-based key encapsulation mechanism from the NTRU-HPS (Highest Performance Secure) family.
 * It provides post-quantum security based on the NTRU problem.
 *
 * Key features:
 * - Lattice-based cryptography (NTRU problem)
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - Optimized for performance
 * - Compact ciphertext (699 bytes)
 *
 * @see {@link https://ntru.org/} - NTRU specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/ntru-hps-2048-509.deno.js`
    : `../../../../dist/ntru-hps-2048-509.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * NTRU-HPS-2048-509-INFO algorithm constants and metadata
 * @type {{readonly name: 'NTRU-HPS-2048-509', readonly identifier: 'NTRU-HPS-2048-509', readonly type: 'kem', readonly securityLevel: 1, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 699, readonly secretKey: 935, readonly ciphertext: 699, readonly sharedSecret: 32}}}
 */
export const NTRU_HPS_2048_509_INFO = {
  name: 'NTRU-HPS-2048-509',
  identifier: 'NTRU-HPS-2048-509',
  type: 'kem',
  securityLevel: 1,
  standardized: false,
  description: 'NTRU-HPS-2048-509 NTRU-HPS (Highest Performance Secure) (NIST Level 1, 128-bit quantum security)',
  keySize: {
    publicKey: 699,
    secretKey: 935,
    ciphertext: 699,
    sharedSecret: 32
  }
};

/**
 * Factory function to create a NTRU-HPS-2048-509 KEM instance
 *
 * @async
 * @function createNTRUHps2048509
 * @returns {Promise<NTRUHps2048509>} Initialized NTRU-HPS-2048-509 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createNTRUHps2048509 } from '@oqs/liboqs-js';
 *
 * const kem = await createNTRUHps2048509();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createNTRUHps2048509() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = NTRU_HPS_2048_509_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('NTRU-HPS-2048-509', 'Failed to create KEM instance');
  }

  return new NTRUHps2048509(wasmModule, kemPtr);
}

/**
 * NTRU-HPS-2048-509 key encapsulation mechanism wrapper class
 *
 * @class NTRUHps2048509
 * @description
 * High-level wrapper for NTRU-HPS-2048-509 KEM operations. Provides secure key generation,
 * encapsulation, and decapsulation with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const kem = await createNTRUHps2048509();
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
export class NTRUHps2048509 {
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
   * Generate a new NTRU-HPS-2048-509 keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 699 bytes
   * console.log('Secret key:', secretKey.length);  // 935 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(NTRU_HPS_2048_509_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(NTRU_HPS_2048_509_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'NTRU-HPS-2048-509', 'Key generation failed');
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
   * @param {Uint8Array} publicKey - Public key for encapsulation (699 bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @returns {Uint8Array} returns.sharedSecret - Shared secret Ciphertext and shared secret
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   *
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
   * console.log('Ciphertext:', ciphertext.length);     // 699 bytes
   * console.log('Shared secret:', sharedSecret.length); // 32 bytes
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const ciphertext = new Uint8Array(NTRU_HPS_2048_509_INFO.keySize.ciphertext);
    const sharedSecret = new Uint8Array(NTRU_HPS_2048_509_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('encapsulate', 'NTRU-HPS-2048-509', 'Encapsulation failed');
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
   * @param {Uint8Array} ciphertext - Ciphertext to decapsulate (699 bytes)
   * @param {Uint8Array} secretKey - Secret key for decapsulation (935 bytes)
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

    const sharedSecret = new Uint8Array(NTRU_HPS_2048_509_INFO.keySize.sharedSecret);

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
        throw new LibOQSOperationError('decapsulate', 'NTRU-HPS-2048-509', 'Decapsulation failed');
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
   * @returns {typeof NTRU_HPS_2048_509_INFO} Algorithm metadata
   *
   * @example
   * console.log(kem.info.name);           // 'NTRU-HPS-2048-509'
   * console.log(kem.info.securityLevel);  // 1
   * console.log(kem.info.keySize);        // { publicKey: 699, secretKey: 935, ciphertext: 699, sharedSecret: 32 }
   */
  get info() {
    return NTRU_HPS_2048_509_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'NTRU-HPS-2048-509');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== NTRU_HPS_2048_509_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${NTRU_HPS_2048_509_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'NTRU-HPS-2048-509'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== NTRU_HPS_2048_509_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${NTRU_HPS_2048_509_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'NTRU-HPS-2048-509'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} ciphertext
   * @throws {LibOQSValidationError} If ciphertext size is invalid
   */
  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== NTRU_HPS_2048_509_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${NTRU_HPS_2048_509_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'NTRU-HPS-2048-509'
      );
    }
  }
}
