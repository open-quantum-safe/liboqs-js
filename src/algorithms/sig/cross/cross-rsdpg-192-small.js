/**
 * @fileoverview CROSS-rsdpg-192-small signature algorithm implementation
 * @module algorithms/sig/cross/cross-rsdpg-192-small
 * @description
 * CROSS-rsdpg-192-small is a code-based signature scheme providing NIST security level 3.
 * It offers optimized for size between signature size and signing/verification speed.
 *
 * Key features:
 * - Small performance profile
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - Variable-length signatures
 * - Code-based cryptography (restricted syndrome decoding problem)
 *
 * @see {@link https://www.cross-crypto.com/} - CROSS specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/cross-rsdpg-192-small.deno.js`
    : `../../../../dist/cross-rsdpg-192-small.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * CROSS-RSDPG-192-SMALL-INFO algorithm constants and metadata
 * @type {{readonly name: 'CROSS-rsdpg-192-small', readonly identifier: 'CROSS-rsdpg-192-small', readonly type: 'sig', readonly securityLevel: 3, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 83, readonly secretKey: 48, readonly signature: 20452}}}
 */
export const CROSS_RSDPG_192_SMALL_INFO = {
  name: 'CROSS-rsdpg-192-small',
  identifier: 'CROSS-rsdpg-192-small',
  type: 'sig',
  securityLevel: 3,
  standardized: false,
  description: 'CROSS-rsdpg-192-small code-based signature (NIST Level 3, 192-bit quantum security, small)',
  keySize: {
    publicKey: 83,
    secretKey: 48,
    signature: 20452
  }
};

/**
 * Factory function to create a CROSS-rsdpg-192-small signature instance
 *
 * @async
 * @function createCrossRsdpg192Small
 * @returns {Promise<CrossRsdpg192Small>} Initialized CROSS-rsdpg-192-small instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createCrossRsdpg192Small } from '@oqs/liboqs-js';
 *
 * const sig = await createCrossRsdpg192Small();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 * sig.destroy();
 */
export async function createCrossRsdpg192Small() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = CROSS_RSDPG_192_SMALL_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('CROSS-rsdpg-192-small', 'Failed to create SIG instance');
  }

  return new CrossRsdpg192Small(wasmModule, sigPtr);
}

/**
 * CROSS-rsdpg-192-small signature algorithm wrapper class
 *
 * @class CrossRsdpg192Small
 * @description
 * High-level wrapper for CROSS-rsdpg-192-small signature operations. Provides secure key generation,
 * message signing, and signature verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createCrossRsdpg192Small(moduleFactory);
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
export class CrossRsdpg192Small {
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
   * Generate a new CROSS-rsdpg-192-small keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 83 bytes
   * console.log('Secret key:', secretKey.length);  // 48 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(CROSS_RSDPG_192_SMALL_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(CROSS_RSDPG_192_SMALL_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'CROSS-rsdpg-192-small', 'Key generation failed');
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
   * Sign a message with CROSS-rsdpg-192-small
   *
   * @async
   * @param {Uint8Array} message - Message to sign (any length)
   * @param {Uint8Array} secretKey - Secret key (48 bytes)
   * @returns {Uint8Array} Signature (variable length, max 20452 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If secret key size is invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Sign this message');
   * const signature = sig.sign(message, secretKey);
   * console.log('Signature length:', signature.length);
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);
    const signaturePtr = this.#wasmModule._malloc(CROSS_RSDPG_192_SMALL_INFO.keySize.signature);
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
        throw new LibOQSOperationError('sign', 'CROSS-rsdpg-192-small', 'Signature generation failed');
      }

      const signatureLen = this.#wasmModule.getValue(signatureLenPtr, 'i32');
      const signature = new Uint8Array(signatureLen);
      signature.set(this.#wasmModule.HEAPU8.subarray(signaturePtr, signaturePtr + signatureLen));

      return signature;
    } finally {
      this.#wasmModule._free(messagePtr);
      this.#wasmModule._free(secretKeyPtr);
      this.#wasmModule._free(signaturePtr);
      this.#wasmModule._free(signatureLenPtr);
    }
  }

  /**
   * Verify a CROSS-rsdpg-192-small signature
   *
   * @async
   * @param {Uint8Array} message - Original message
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key (83 bytes)
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
    this.#validateMessage(message);
    this.#validatePublicKey(publicKey);
    this.#validateSignature(signature);

    const messagePtr = this.#wasmModule._malloc(message.length);
    const signaturePtr = this.#wasmModule._malloc(signature.length);
    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);

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
   * @returns {typeof CROSS_RSDPG_192_SMALL_INFO} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'CROSS-rsdpg-192-small'
   * console.log(sig.info.securityLevel);  // 3
   * console.log(sig.info.keySize);        // { publicKey: 83, secretKey: 48, signature: 20452 }
   */
  get info() {
    return CROSS_RSDPG_192_SMALL_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'CROSS-rsdpg-192-small');
    }
  }

  /**
   * @private
   * @param {Uint8Array} message
   * @throws {LibOQSValidationError} If message is invalid
   */
  #validateMessage(message) {
    if (!isUint8Array(message)) {
      throw new LibOQSValidationError(
        'Message must be Uint8Array',
        'CROSS-rsdpg-192-small'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== CROSS_RSDPG_192_SMALL_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${CROSS_RSDPG_192_SMALL_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'CROSS-rsdpg-192-small'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== CROSS_RSDPG_192_SMALL_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${CROSS_RSDPG_192_SMALL_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'CROSS-rsdpg-192-small'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature size is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature)) {
      throw new LibOQSValidationError(
        'Signature must be Uint8Array',
        'CROSS-rsdpg-192-small'
      );
    }
    if (signature.length === 0 || signature.length > CROSS_RSDPG_192_SMALL_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature length: expected up to ${CROSS_RSDPG_192_SMALL_INFO.keySize.signature} bytes, got ${signature.length}`,
        'CROSS-rsdpg-192-small'
      );
    }
  }
}
