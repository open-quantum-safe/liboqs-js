/**
 * @fileoverview SNOVA-24-5-4-SHAKE-esk signature algorithm implementation
 * @module algorithms/sig/snova/snova-24-5-4-shake-esk
 * @description
 * SNOVA-24-5-4-SHAKE-esk is a multivariate quadratic signature scheme from the SNOVA family.
 * This is the SHAKE variant with expanded secret key for faster signing.
 *
 * Key features:
 * - Multivariate quadratic cryptography
 * - Security Level 1 (128-bit classical, quantum-resistant)
 * - Expanded secret key for faster signing
 * - SHAKE-based hash function
 * - Compact signatures (248 bytes)
 *
 * @see {@link https://snova.pqclab.org/} - SNOVA specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/snova-24-5-4-shake-esk.deno.js`
    : `../../../../dist/snova-24-5-4-shake-esk.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * SNOVA-24-5-4-SHAKE-ESK-INFO algorithm constants and metadata
 * @type {{readonly name: 'SNOVA-24-5-4-SHAKE-esk', readonly identifier: 'SNOVA_24_5_4_SHAKE_esk', readonly type: 'sig', readonly securityLevel: 1, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 1016, readonly secretKey: 36848, readonly signature: 248}}}
 */
export const SNOVA_24_5_4_SHAKE_ESK_INFO = {
  name: 'SNOVA-24-5-4-SHAKE-esk',
  identifier: 'SNOVA_24_5_4_SHAKE_esk',
  type: 'sig',
  securityLevel: 1,
  standardized: false,
  description: 'SNOVA-24-5-4-SHAKE-esk multivariate signature scheme (NIST Level 1, 128-bit quantum security, SHAKE variant with expanded secret key for faster signing)',
  keySize: {
    publicKey: 1016,
    secretKey: 36848,
    signature: 248
  }
};

/**
 * Factory function to create a SNOVA-24-5-4-SHAKE-esk signature instance
 *
 * @async
 * @function createSnova2454ShakeEsk
 * @returns {Promise<Snova2454ShakeEsk>} Initialized SNOVA-24-5-4-SHAKE-esk instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createSnova2454ShakeEsk } from '@oqs/liboqs-js';
 *
 * const sig = await createSnova2454ShakeEsk();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 * sig.destroy();
 */
export async function createSnova2454ShakeEsk() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = SNOVA_24_5_4_SHAKE_ESK_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('SNOVA-24-5-4-SHAKE-esk', 'Failed to create SIG instance');
  }

  return new Snova2454ShakeEsk(wasmModule, sigPtr);
}

/**
 * SNOVA-24-5-4-SHAKE-esk digital signature wrapper class
 *
 * @class Snova2454ShakeEsk
 * @description
 * High-level wrapper for SNOVA-24-5-4-SHAKE-esk signature operations. Provides secure key generation,
 * signing, and verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createSnova2454ShakeEsk();
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
 *
 * // Cleanup
 * sig.destroy();
 */
export class Snova2454ShakeEsk {
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
   * Generate a new SNOVA-24-5-4-SHAKE-esk keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 1016 bytes
   * console.log('Secret key:', secretKey.length);  // 36848 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'SNOVA-24-5-4-SHAKE-esk', 'Key generation failed');
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
   * Sign a message using the secret key
   *
   * @async
   * @param {Uint8Array} message - Message to sign (arbitrary length)
   * @param {Uint8Array} secretKey - Secret key for signing (36848 bytes)
   * @returns {Uint8Array} Digital signature (up to 248 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Hello!');
   * const signature = sig.sign(message, secretKey);
   * console.log('Signature:', signature.length); // 248 bytes
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const signature = new Uint8Array(SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.signature);
    const sigPtr = this.#wasmModule._malloc(signature.length);
    const sigLenPtr = this.#wasmModule._malloc(8); // size_t
    const msgPtr = this.#wasmModule._malloc(message.length);
    const skPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      this.#wasmModule.HEAPU8.set(message, msgPtr);
      this.#wasmModule.HEAPU8.set(secretKey, skPtr);
      this.#wasmModule.setValue(sigLenPtr, signature.length, 'i64');

      const result = this.#wasmModule._OQS_SIG_sign(
        this.#sigPtr,
        sigPtr,
        sigLenPtr,
        msgPtr,
        message.length,
        skPtr
      );

      if (result !== 0) {
        throw new LibOQSOperationError('sign', 'SNOVA-24-5-4-SHAKE-esk', 'Signing failed');
      }

      const actualSigLen = this.#wasmModule.getValue(sigLenPtr, 'i32');
      const actualSignature = new Uint8Array(actualSigLen);
      actualSignature.set(this.#wasmModule.HEAPU8.subarray(sigPtr, sigPtr + actualSigLen));

      return actualSignature;
    } finally {
      this.#wasmModule._free(sigPtr);
      this.#wasmModule._free(sigLenPtr);
      this.#wasmModule._free(msgPtr);
      this.#wasmModule._free(skPtr);
    }
  }

  /**
   * Verify a signature against a message using the public key
   *
   * @async
   * @param {Uint8Array} message - Original message that was signed
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key for verification (1016 bytes)
   * @returns {boolean} True if signature is valid, false otherwise
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   *
   * @example
   * const isValid = sig.verify(message, signature, publicKey);
   * if (isValid) {
   *   console.log('Signature is valid!');
   * }
   */
  verify(message, signature, publicKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSignature(signature);
    this.#validatePublicKey(publicKey);

    const msgPtr = this.#wasmModule._malloc(message.length);
    const sigPtr = this.#wasmModule._malloc(signature.length);
    const pkPtr = this.#wasmModule._malloc(publicKey.length);

    try {
      this.#wasmModule.HEAPU8.set(message, msgPtr);
      this.#wasmModule.HEAPU8.set(signature, sigPtr);
      this.#wasmModule.HEAPU8.set(publicKey, pkPtr);

      const result = this.#wasmModule._OQS_SIG_verify(
        this.#sigPtr,
        msgPtr,
        message.length,
        sigPtr,
        signature.length,
        pkPtr
      );

      return result === 0;
    } finally {
      this.#wasmModule._free(msgPtr);
      this.#wasmModule._free(sigPtr);
      this.#wasmModule._free(pkPtr);
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
   * @returns {typeof SNOVA_24_5_4_SHAKE_ESK_INFO} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'SNOVA-24-5-4-SHAKE-esk'
   * console.log(sig.info.securityLevel);  // 1
   * console.log(sig.info.keySize);        // { publicKey: 1016, secretKey: 36848, signature: 248 }
   */
  get info() {
    return SNOVA_24_5_4_SHAKE_ESK_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'SNOVA-24-5-4-SHAKE-esk');
    }
  }

  /**
   * @private
   * @param {Uint8Array} message
   * @throws {LibOQSValidationError} If message is invalid
   */
  #validateMessage(message) {
    if (!ArrayBuffer.isView(message) || message.constructor.name !== 'Uint8Array') {
      throw new LibOQSValidationError(
        'Message must be Uint8Array',
        'SNOVA-24-5-4-SHAKE-esk'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'SNOVA-24-5-4-SHAKE-esk'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'SNOVA-24-5-4-SHAKE-esk'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} signature
   * @throws {LibOQSValidationError} If signature is invalid
   */
  #validateSignature(signature) {
    if (!isUint8Array(signature)) {
      throw new LibOQSValidationError(
        'Signature must be Uint8Array',
        'SNOVA-24-5-4-SHAKE-esk'
      );
    }
    if (signature.length === 0 || signature.length > SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature length: expected up to ${SNOVA_24_5_4_SHAKE_ESK_INFO.keySize.signature} bytes, got ${signature.length}`,
        'SNOVA-24-5-4-SHAKE-esk'
      );
    }
  }
}
