/**
 * @fileoverview SNOVA-29-6-5 signature algorithm implementation
 * @module algorithms/sig/snova/snova-29-6-5
 * @description
 * SNOVA-29-6-5 is a multivariate quadratic signature scheme from the SNOVA family.
 * This is the standard variant.
 *
 * Key features:
 * - Multivariate quadratic cryptography
 * - Security Level 3 (192-bit classical, quantum-resistant)
 * - Compact secret key (48 bytes)
 * - Standard hash function
 * - Compact signatures (454 bytes)
 *
 * @see {@link https://snova.pqclab.org/} - SNOVA specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/snova-29-6-5.deno.js`
    : `../../../../dist/snova-29-6-5.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * SNOVA-29-6-5-INFO algorithm constants and metadata
 * @type {{readonly name: 'SNOVA-29-6-5', readonly identifier: 'SNOVA_29_6_5', readonly type: 'sig', readonly securityLevel: 3, readonly standardized: false, readonly description: string, readonly keySize: {readonly publicKey: 2716, readonly secretKey: 48, readonly signature: 454}}}
 */
export const SNOVA_29_6_5_INFO = {
  name: 'SNOVA-29-6-5',
  identifier: 'SNOVA_29_6_5',
  type: 'sig',
  securityLevel: 3,
  standardized: false,
  description: 'SNOVA-29-6-5 multivariate signature scheme (NIST Level 3, 192-bit quantum security, standard variant)',
  keySize: {
    publicKey: 2716,
    secretKey: 48,
    signature: 454
  }
};

/**
 * Factory function to create a SNOVA-29-6-5 signature instance
 *
 * @async
 * @function createSnova2965
 * @returns {Promise<Snova2965>} Initialized SNOVA-29-6-5 instance
 * @throws {LibOQSInitError} If module initialization fails
 *
 * @example
 * import { createSnova2965 } from '@oqs/liboqs-js';
 *
 * const sig = await createSnova2965();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 * sig.destroy();
 */
export async function createSnova2965() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = SNOVA_29_6_5_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('SNOVA-29-6-5', 'Failed to create SIG instance');
  }

  return new Snova2965(wasmModule, sigPtr);
}

/**
 * SNOVA-29-6-5 digital signature wrapper class
 *
 * @class Snova2965
 * @description
 * High-level wrapper for SNOVA-29-6-5 signature operations. Provides secure key generation,
 * signing, and verification with automatic memory management.
 *
 * Memory Management:
 * - All WASM memory is managed internally
 * - Call destroy() when finished to free resources
 * - Do not use instance after calling destroy()
 *
 * @example
 * const sig = await createSnova2965();
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
export class Snova2965 {
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
   * Generate a new SNOVA-29-6-5 keypair
   *
   * @async
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSOperationError} If key generation fails
   *
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   * console.log('Public key:', publicKey.length);  // 2716 bytes
   * console.log('Secret key:', secretKey.length);  // 48 bytes
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(SNOVA_29_6_5_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(SNOVA_29_6_5_INFO.keySize.secretKey);

    const publicKeyPtr = this.#wasmModule._malloc(publicKey.length);
    const secretKeyPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, publicKeyPtr, secretKeyPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'SNOVA-29-6-5', 'Key generation failed');
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
   * @param {Uint8Array} secretKey - Secret key for signing (48 bytes)
   * @returns {Uint8Array} Digital signature (up to 454 bytes)
   * @throws {LibOQSError} If instance is destroyed
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If signing fails
   *
   * @example
   * const message = new TextEncoder().encode('Hello!');
   * const signature = sig.sign(message, secretKey);
   * console.log('Signature:', signature.length); // 454 bytes
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const signature = new Uint8Array(SNOVA_29_6_5_INFO.keySize.signature);
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
        throw new LibOQSOperationError('sign', 'SNOVA-29-6-5', 'Signing failed');
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
   * @param {Uint8Array} publicKey - Public key for verification (2716 bytes)
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
   * @returns {typeof SNOVA_29_6_5_INFO} Algorithm metadata
   *
   * @example
   * console.log(sig.info.name);           // 'SNOVA-29-6-5'
   * console.log(sig.info.securityLevel);  // 3
   * console.log(sig.info.keySize);        // { publicKey: 2716, secretKey: 48, signature: 454 }
   */
  get info() {
    return SNOVA_29_6_5_INFO;
  }

  /**
   * @private
   * @throws {LibOQSError} If instance is destroyed
   */
  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'SNOVA-29-6-5');
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
        'SNOVA-29-6-5'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} publicKey
   * @throws {LibOQSValidationError} If public key size is invalid
   */
  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== SNOVA_29_6_5_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${SNOVA_29_6_5_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'SNOVA-29-6-5'
      );
    }
  }

  /**
   * @private
   * @param {Uint8Array} secretKey
   * @throws {LibOQSValidationError} If secret key size is invalid
   */
  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== SNOVA_29_6_5_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${SNOVA_29_6_5_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'SNOVA-29-6-5'
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
        'SNOVA-29-6-5'
      );
    }
    if (signature.length === 0 || signature.length > SNOVA_29_6_5_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature length: expected up to ${SNOVA_29_6_5_INFO.keySize.signature} bytes, got ${signature.length}`,
        'SNOVA-29-6-5'
      );
    }
  }
}
