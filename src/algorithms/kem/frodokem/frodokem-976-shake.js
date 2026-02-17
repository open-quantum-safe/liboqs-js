/**
 * @fileoverview FrodoKEM-976-SHAKE KEM algorithm implementation
 * @module algorithms/kem/frodokem/frodokem-976-shake
 * @description
 * FrodoKEM-976-SHAKE is a lattice-based key encapsulation mechanism providing NIST security level 3.
 * It uses learning with errors (LWE) and SHAKE for pseudorandom generation.
 *
 * Key features:
 * - Lattice-based cryptography (LWE problem)
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - Conservative security margin
 * - SHAKE-based pseudorandom generation
 *
 * @see {@link https://frodokem.org/} - FrodoKEM specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/frodokem-976-shake.deno.js`
    : `../../../../dist/frodokem-976-shake.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * FRODOKEM-976-SHAKE-INFO algorithm constants and metadata
 * @type {{readonly name: 'FrodoKEM-976-SHAKE', readonly identifier: 'FrodoKEM-976-SHAKE', readonly type: 'kem', readonly securityLevel: 3, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 15632, readonly secretKey: 31296, readonly ciphertext: 15792, readonly sharedSecret: 24}}}
 */
export const FRODOKEM_976_SHAKE_INFO = {
  name: 'FrodoKEM-976-SHAKE',
  identifier: 'FrodoKEM-976-SHAKE',
  type: 'kem',
  securityLevel: 3,
  standardized: false,
  description: 'FrodoKEM-976-SHAKE lattice-based KEM (NIST Level 3, 192-bit quantum security, SHAKE)',
  keySize: {
    publicKey: 15632,
    secretKey: 31296,
    ciphertext: 15792,
    sharedSecret: 24
  }
};

/**
 * Factory function to create a FrodoKEM-976-SHAKE KEM instance
 *
 * @async
 * @function createFrodoKEM976SHAKE
 * @returns {Promise<FrodoKEM976SHAKE>} Initialized FrodoKEM-976-SHAKE instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createFrodoKEM976SHAKE } from '@oqs/liboqs-js';
 *
 * const kem = await createFrodoKEM976SHAKE();
 * const { publicKey, secretKey } = kem.generateKeyPair();
 * kem.destroy();
 */
export async function createFrodoKEM976SHAKE() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = FRODOKEM_976_SHAKE_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const kemPtr = wasmModule._OQS_KEM_new(namePtr);
  wasmModule._free(namePtr);

  if (!kemPtr) {
    throw new LibOQSInitError('FrodoKEM-976-SHAKE', 'Failed to create KEM instance');
  }

  return new FrodoKEM976SHAKE(wasmModule, kemPtr);
}

/**
 * FrodoKEM-976-SHAKE key encapsulation mechanism wrapper class
 *
 * @class FrodoKEM976SHAKE
 * @description
 * High-level wrapper for FrodoKEM-976-SHAKE KEM operations. Provides secure key generation,
 * encapsulation, and decapsulation with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const kem = await createFrodoKEM976SHAKE();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = kem.generateKeyPair();
 *
 * // Encapsulate
 * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
 *
 * // Decapsulate
 * const recoveredSecret = kem.decapsulate(ciphertext, secretKey);
 *
 * // Cleanup
 * kem.destroy();
 */
export class FrodoKEM976SHAKE {
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
   * Generate a new FrodoKEM-976-SHAKE keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = kem.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 15632 bytes
   * console.log('Secret key:', secretKey.length);  // 31296 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(FRODOKEM_976_SHAKE_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(FRODOKEM_976_SHAKE_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_KEM_keypair(this.#kemPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'FrodoKEM-976-SHAKE', 'Key generation failed');
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
   * Encapsulate a shared secret using a public key
   *
   * @async
   * @param {Uint8Array} publicKey - Public key (15632 bytes)
   * @returns {{ciphertext: Uint8Array, sharedSecret: Uint8Array}}
   * @returns {Uint8Array} returns.sharedSecret - Shared secret Ciphertext and shared secret
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key size is invalid
   * @throws {LibOQSOperationError} If encapsulation fails
   *
   * @example
   * const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
   * console.log('Ciphertext:', ciphertext.length);      // 15792 bytes
   * console.log('Shared secret:', sharedSecret.length); // 24 bytes
   */
  encapsulate(publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);

    const ciphertext = new Uint8Array(FRODOKEM_976_SHAKE_INFO.keySize.ciphertext);
    const sharedSecret = new Uint8Array(FRODOKEM_976_SHAKE_INFO.keySize.sharedSecret);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);

    try {
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_KEM_encaps(
        this.#kemPtr,
        ciphertextPtr,
        sharedSecretPtr,
        publicKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('encapsulate', 'FrodoKEM-976-SHAKE', 'Encapsulation failed');
      }

      ciphertext.set(this.#wasmModule.HEAPU8.subarray(ciphertextPtr, ciphertextPtr + ciphertext.length));
      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

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
   * @async
   * @param {Uint8Array} ciphertext - Ciphertext (15792 bytes)
   * @param {Uint8Array} secretKey - Secret key (31296 bytes)
   * @returns {Uint8Array} Shared secret (24 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If ciphertext or secret key size is invalid
   * @throws {LibOQSOperationError} If decapsulation fails
   *
   * @example
   * const sharedSecret = kem.decapsulate(ciphertext, secretKey);
   * console.log('Recovered secret:', sharedSecret.length); // 24 bytes
   */
  decapsulate(ciphertext, secretKey) {
    this.#checkDestroyed();
    this.#validateCiphertext(ciphertext);
    this.#validateSecretKey(secretKey);

    const sharedSecret = new Uint8Array(FRODOKEM_976_SHAKE_INFO.keySize.sharedSecret);

    const ciphertextPtr = this.#wasmModule._malloc(ciphertext.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);
    const sharedSecretPtr = this.#wasmModule._malloc(sharedSecret.length);

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
        throw new LibOQSOperationError('decapsulate', 'FrodoKEM-976-SHAKE', 'Decapsulation failed');
      }

      sharedSecret.set(this.#wasmModule.HEAPU8.subarray(sharedSecretPtr, sharedSecretPtr + sharedSecret.length));

      return sharedSecret;
    } finally {
      this.#wasmModule._free(ciphertextPtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(sharedSecretPtr);
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
   * @returns {typeof FRODOKEM_976_SHAKE_INFO} Algorithm metadata
   *
   * @example
   * console.log(kem.info.name);           // 'FrodoKEM-976-SHAKE'
   * console.log(kem.info.securityLevel);  // 3
   * console.log(kem.info.keySize);        // { publicKey: 15632, secretKey: 31296, ciphertext: 15792, sharedSecret: 24 }
   */
  get info() {
    return FRODOKEM_976_SHAKE_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'FrodoKEM-976-SHAKE');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== FRODOKEM_976_SHAKE_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${FRODOKEM_976_SHAKE_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'FrodoKEM-976-SHAKE'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== FRODOKEM_976_SHAKE_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${FRODOKEM_976_SHAKE_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'FrodoKEM-976-SHAKE'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} ciphertext
   * @throws {LibOQSValidationError} If ciphertext size is invalid
   */
  #validateCiphertext(ciphertext) {
    if (!isUint8Array(ciphertext) || ciphertext.length !== FRODOKEM_976_SHAKE_INFO.keySize.ciphertext) {
      throw new LibOQSValidationError(
        `Invalid ciphertext: expected ${FRODOKEM_976_SHAKE_INFO.keySize.ciphertext} bytes, got ${ciphertext?.length ?? 'null'}`,
        'FrodoKEM-976-SHAKE'
      );
    }
  }
}
