/**
 * @fileoverview Falcon-512 signature algorithm implementation
 * @module algorithms/sig/falcon/falcon-512
 * @description
 * Falcon-512 is a lattice-based signature scheme providing NIST security level 1.
 * It offers compact signatures and fast verification, based on NTRU lattices and Fast Fourier sampling.
 *
 * Key features:
 * - Compact signatures (~752 bytes average)
 * - Fast verification
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - Variable-length signatures
 *
 * @see {@link https://falcon-sign.info/} - Falcon specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/falcon-512.deno.js`
    : `../../../../dist/falcon-512.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * FALCON-512-INFO algorithm constants and metadata
 * @type {{readonly name: 'Falcon-512', readonly identifier: 'Falcon-512', readonly type: 'sig', readonly securityLevel: 1, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 897, readonly secretKey: 1281, readonly signature: 752}}}
 */
export const FALCON_512_INFO = {
  name: 'Falcon-512',
  identifier: 'Falcon-512',
  type: 'sig',
  securityLevel: 1,
  standardized: false,
  description: 'Falcon-512 lattice-based signature (NIST Level 1, 128-bit quantum security)',
  keySize: {
    publicKey: 897,
    secretKey: 1281,
    signature: 752
  }
};

/**
 * Factory function to create a Falcon-512 signature instance
 *
 * @async
 * @function createFalcon512
 * @returns {Promise<Falcon512>} Initialized Falcon-512 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createFalcon512 } from '@oqs/liboqs-js';
 *
 * const sig = await createFalcon512();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 * sig.destroy();
 */
export async function createFalcon512() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = FALCON_512_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('Falcon-512', 'Failed to create SIG instance');
  }

  return new Falcon512(wasmModule, sigPtr);
}

/**
 * Falcon-512 signature algorithm wrapper class
 *
 * @class Falcon512
 * @description
 * High-level wrapper for Falcon-512 signature operations. Provides secure key generation,
 * message signing, and signature verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createFalcon512();
 *
 * // Generate keypair
 * const { publicKey, secretKey } = sig.generateKeyPair();
 *
 * // Sign message
 * const message = new TextEncoder().encode('Hello, quantum world!');
 * const signature = sig.sign(message, secretKey);
 *
 * // Verify signature
 * const isValid = sig.verify(message, signature, publicKey);
 * console.log('Valid:', isValid); // true
 *
 * // Cleanup
 * sig.destroy();
 */
export class Falcon512 {
  /** @type {Object} @private */ #wasmModule;
  /** @type {number} @private */ #sigPtr;
  /** @type {boolean} @private */ #destroyed = false;

  /**
   * @private
   * @constructor
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} sigPtr - Pointer to OQS_SIG structure
   */
  constructor(wasmModule, sigPtr) {
    this.#wasmModule = wasmModule;
    this.#sigPtr = sigPtr;
  }

  /**
   * Generate a new Falcon-512 keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 897 bytes
   * console.log('Secret key:', secretKey.length);  // 1281 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKeyPtr = this.#wasmModule._malloc(FALCON_512_INFO.keySize.publicKey);
    const secretKeyPtr = this.#wasmModule._malloc(FALCON_512_INFO.keySize.secretKey);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'Falcon-512', 'Key generation failed');
      }

      const publicKey = new Uint8Array(
        this.#wasmModule.HEAPU8.buffer,
        publicKeyPtr,
        FALCON_512_INFO.keySize.publicKey
      ).slice();

      const secretKey = new Uint8Array(
        this.#wasmModule.HEAPU8.buffer,
        secretKeyPtr,
        FALCON_512_INFO.keySize.secretKey
      ).slice();

      return { publicKey, secretKey };
    } finally {
      this.#wasmModule._free(publicKeyPtr);
      this.#wasmModule._free(secretKeyPtr);
    }
  }

  /**
   * Sign a message with Falcon-512
   *
   * @async
   * @param {Uint8Array} message - Message to sign (any length)
   * @param {Uint8Array} secretKey - Secret key (1281 bytes)
   * @returns {Uint8Array} Signature (variable length, max 752 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If secret key size is invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Sign this message');
   * const signature = sig.sign(message, secretKey);
   * console.log('Signature length:', signature.length); // ~752 bytes (variable)
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateSecretKey(secretKey);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const secretKeyPtr = this.#wasmModule._malloc(FALCON_512_INFO.keySize.secretKey);
    const signaturePtr = this.#wasmModule._malloc(FALCON_512_INFO.keySize.signature);
    const signatureLenPtr = this.#wasmModule._malloc(8);

    try {
      this.#wasmModule.HEAPU8.set(message, messagePtr);
      this.#wasmModule.HEAPU8.set(secretKey, secretKeyPtr);

      const result = this.#wasmModule._OQS_SIG_sign(
        this.#sigPtr,
        signaturePtr,
        signatureLenPtr,
        messagePtr,
        message.length,
        secretKeyPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('sign', 'Falcon-512', 'Signature generation failed');
      }

      const signatureLen = this.#wasmModule.getValue(signatureLenPtr, 'i32');

      const signature = new Uint8Array(
        this.#wasmModule.HEAPU8.buffer,
        signaturePtr,
        signatureLen
      ).slice();

      return signature;
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(signatureLenPtr);
    }
  }

  /**
   * Verify a Falcon-512 signature
   *
   * @async
   * @param {Uint8Array} message - Original message
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key (897 bytes)
   * @returns {boolean} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If public key or signature size is invalid
   *
   * @example
   * const isValid = sig.verify(message, signature, publicKey);
   * if (isValid) {
   *   console.log('Signature is valid!');
   * } else {
   *   console.log('Signature verification failed');
   * }
   */
  verify(message, signature, publicKey) {
    this.#checkDestroyed();
    this.#validatePublicKey(publicKey);
    this.#validateSignature(signature);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const signaturePtr = this.#wasmModule._malloc(signature.length);
    const publicKeyPtr = this.#wasmModule._malloc(FALCON_512_INFO.keySize.publicKey);

    try {
      this.#wasmModule.HEAPU8.set(message, messagePtr);
      this.#wasmModule.HEAPU8.set(signature, signaturePtr);
      this.#wasmModule.HEAPU8.set(publicKey, publicKeyPtr);

      const result = this.#wasmModule._OQS_SIG_verify(
        this.#sigPtr,
        messagePtr,
        message.length,
        signaturePtr,
        signature.length,
        publicKeyPtr
      );

      return result === 0;
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(publicKeyPtr);
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
   * sig.destroy();
   * // sig is now unusable
   */
  destroy() {
    if (!this.#destroyed && this.#sigPtr) {
      this.#wasmModule._OQS_SIG_free(this.#sigPtr);
      this.#sigPtr = null;
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
   * @returns {typeof FALCON_512_INFO} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'Falcon-512'
   * console.log(sig.info.securityLevel);  // 1
   * console.log(sig.info.keySize);        // { publicKey: 897, secretKey: 1281, signature: 752 }
   */
  get info() {
    return FALCON_512_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'Falcon-512');
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== FALCON_512_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key size: expected ${FALCON_512_INFO.keySize.publicKey} bytes, got ${publicKey.length}`,
        'Falcon-512'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== FALCON_512_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key size: expected ${FALCON_512_INFO.keySize.secretKey} bytes, got ${secretKey.length}`,
        'Falcon-512'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature size is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature) || signature.length === 0 || signature.length > FALCON_512_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature size: expected 1-${FALCON_512_INFO.keySize.signature} bytes, got ${signature.length}`,
        'Falcon-512'
      );
    }
  }
}
