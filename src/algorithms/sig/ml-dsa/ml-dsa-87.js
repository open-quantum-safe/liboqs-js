/**
 * @fileoverview ML-DSA-87 signature algorithm implementation
 * @module algorithms/sig/ml-dsa/ml-dsa-87
 * @description
 * ML-DSA-87 is a lattice-based digital signature algorithm providing NIST security level 5.
 * It is part of the NIST FIPS 204 standard (Module-Lattice-Based Digital Signature Algorithm).
 *
 * Key features:
 * - Lattice-based cryptography (Module-LWE and Module-SIS problems)
 * - Security Level 5 (256-bit classical, quantum-resistant)
 * - NIST FIPS 204 standardized
 * - Strong existential unforgeability under chosen message attack (SUF-CMA)
 * - Deterministic signing with optional hedged mode
 *
 * @see {@link https://csrc.nist.gov/pubs/fips/204/final} - NIST FIPS 204 specification
 */

import { LibOQSError, LibOQSInitError, LibOQSOperationError, LibOQSValidationError } from '../../../core/errors.js';
import { isUint8Array } from '../../../core/validation.js';

// Dynamic module loading for cross-runtime compatibility
async function loadModule() {
  const isDeno = typeof Deno !== 'undefined';
  const modulePath = isDeno
    ? `../../../../dist/ml-dsa-87.deno.js`
    : `../../../../dist/ml-dsa-87.min.js`;

  const module = await import(modulePath);
  return module.default;
}

/**
 * ML-DSA-87-INFO algorithm constants and metadata
 * @type {{readonly name: 'ML-DSA-87', readonly identifier: 'ML-DSA-87', readonly type: 'sig', readonly securityLevel: 5, readonly standardized: true, readonly description: string, readonly keySize: {readonly publicKey: 2592, readonly secretKey: 4896, readonly signature: 4627}}}
 */
export const ML_DSA_87_INFO = {
  name: 'ML-DSA-87',
  identifier: 'ML-DSA-87',
  type: 'sig',
  securityLevel: 5,
  standardized: true,
  description: 'NIST FIPS 204 ML-DSA-87 lattice-based signature (NIST Level 5, 256-bit quantum security)',
  keySize: {
    publicKey: 2592,
    secretKey: 4896,
    signature: 4627
  }
};

/**
 * Load and initialize ML-DSA-87 module
 * @returns {Promise<MLDSA87>} Initialized ML-DSA-87 instance
 * @throws {LibOQSInitError} If initialization fails
 * @example
 * import { createMLDSA87 } from '@oqs/liboqs-js';
 * const sig = await createMLDSA87();
 */
export async function createMLDSA87() {
  const moduleFactory = await loadModule();
  const wasmModule = await moduleFactory();
  wasmModule._OQS_init();

  const algoName = ML_DSA_87_INFO.identifier;
  const nameLen = wasmModule.lengthBytesUTF8(algoName);
  const namePtr = wasmModule._malloc(nameLen + 1);
  wasmModule.stringToUTF8(algoName, namePtr, nameLen + 1);

  const sigPtr = wasmModule._OQS_SIG_new(namePtr);
  wasmModule._free(namePtr);

  if (!sigPtr) {
    throw new LibOQSInitError('ML-DSA-87', 'Failed to create SIG instance');
  }

  return new MLDSA87(wasmModule, sigPtr);
}

/**
 * ML-DSA-87 digital signature wrapper class
 *
 * Provides high-level interface for ML-DSA-87 digital signature operations.
 * Automatically manages WASM memory and validates inputs.
 *
 * @class MLDSA87
 * @example
 * const sig = await createMLDSA87();
 * const { publicKey, secretKey } = sig.generateKeyPair();
 *
 * const message = new TextEncoder().encode('Hello, quantum world!');
 * const signature = sig.sign(message, secretKey);
 *
 * const isValid = sig.verify(message, signature, publicKey);
 * console.log('Valid:', isValid); // true
 *
 * sig.destroy();
 */
export class MLDSA87 {
  #wasmModule;
  #sigPtr;
  #destroyed = false;

  /**
   * @param {Object} wasmModule - Emscripten WASM module
   * @param {number} sigPtr - Pointer to OQS_SIG structure
   * @private
   */
  constructor(wasmModule, sigPtr) {
    this.#wasmModule = wasmModule;
    this.#sigPtr = sigPtr;
  }

  /**
   * Generate a new ML-DSA-87 keypair
   *
   * Creates a new public/private keypair for digital signatures.
   * The secret key must be kept confidential.
   *
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   * @throws {LibOQSOperationError} If key generation fails
   * @example
   * const { publicKey, secretKey } = sig.generateKeyPair();
   */
  generateKeyPair() {
    this.#checkDestroyed();

    const publicKey = new Uint8Array(ML_DSA_87_INFO.keySize.publicKey);
    const secretKey = new Uint8Array(ML_DSA_87_INFO.keySize.secretKey);

    const pkPtr = this.#wasmModule._malloc(publicKey.length);
    const skPtr = this.#wasmModule._malloc(secretKey.length);

    try {
      const result = this.#wasmModule._OQS_SIG_keypair(this.#sigPtr, pkPtr, skPtr);

      if (result !== 0) {
        throw new LibOQSOperationError('generateKeyPair', 'ML-DSA-87', 'Key generation failed');
      }

      publicKey.set(this.#wasmModule.HEAPU8.subarray(pkPtr, pkPtr + publicKey.length));
      secretKey.set(this.#wasmModule.HEAPU8.subarray(skPtr, skPtr + secretKey.length));

      return { publicKey, secretKey };
    } finally {
      this.#wasmModule._free(pkPtr);
      this.#wasmModule._free(skPtr);
    }
  }

  /**
   * Sign a message using the secret key
   *
   * Generates a digital signature for the provided message.
   * The signature can be verified using the corresponding public key.
   *
   * @param {Uint8Array} message - Message to sign (arbitrary length)
   * @param {Uint8Array} secretKey - Secret key for signing (4896 bytes)
   * @returns {Uint8Array} Digital signature (up to 4627 bytes)
   * @throws {LibOQSValidationError} If inputs are invalid
   * @throws {LibOQSOperationError} If signing fails
   * @example
   * const message = new TextEncoder().encode('Hello!');
   * const signature = sig.sign(message, secretKey);
   */
  sign(message, secretKey) {
    this.#checkDestroyed();
    this.#validateMessage(message);
    this.#validateSecretKey(secretKey);

    const signature = new Uint8Array(ML_DSA_87_INFO.keySize.signature);
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
        throw new LibOQSOperationError('sign', 'ML-DSA-87', 'Signing failed');
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
   * Verifies that the signature is valid for the given message and public key.
   *
   * @param {Uint8Array} message - Original message that was signed
   * @param {Uint8Array} signature - Signature to verify
   * @param {Uint8Array} publicKey - Public key for verification (2592 bytes)
   * @returns {boolean} True if signature is valid, false otherwise
   * @throws {LibOQSValidationError} If inputs are invalid
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
   * Clean up WASM resources
   *
   * Frees the native signature structure. The instance cannot be used after calling destroy().
   *
   * @example
   * sig.destroy();
   */
  destroy() {
    if (!this.#destroyed) {
      if (this.#sigPtr) {
        this.#wasmModule._OQS_SIG_free(this.#sigPtr);
        this.#sigPtr = null;
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
   * Get algorithm information
   * @returns {typeof ML_DSA_87_INFO} Algorithm metadata
   */
  get info() {
    return ML_DSA_87_INFO;
  }

  #checkDestroyed() {
    if (this.#destroyed) {
      throw new LibOQSError('Instance has been destroyed', 'ML-DSA-87');
    }
  }

  #validateMessage(message) {
    if (!ArrayBuffer.isView(message) || message.constructor.name !== 'Uint8Array') {
      throw new LibOQSValidationError(
        'Message must be Uint8Array',
        'ML-DSA-87'
      );
    }
  }

  #validatePublicKey(publicKey) {
    if (!isUint8Array(publicKey) || publicKey.length !== ML_DSA_87_INFO.keySize.publicKey) {
      throw new LibOQSValidationError(
        `Invalid public key: expected ${ML_DSA_87_INFO.keySize.publicKey} bytes, got ${publicKey?.length ?? 'null'}`,
        'ML-DSA-87'
      );
    }
  }

  #validateSecretKey(secretKey) {
    if (!isUint8Array(secretKey) || secretKey.length !== ML_DSA_87_INFO.keySize.secretKey) {
      throw new LibOQSValidationError(
        `Invalid secret key: expected ${ML_DSA_87_INFO.keySize.secretKey} bytes, got ${secretKey?.length ?? 'null'}`,
        'ML-DSA-87'
      );
    }
  }

  #validateSignature(signature) {
    if (!isUint8Array(signature)) {
      throw new LibOQSValidationError(
        'Signature must be Uint8Array',
        'ML-DSA-87'
      );
    }
    if (signature.length === 0 || signature.length > ML_DSA_87_INFO.keySize.signature) {
      throw new LibOQSValidationError(
        `Invalid signature length: expected up to ${ML_DSA_87_INFO.keySize.signature} bytes, got ${signature.length}`,
        'ML-DSA-87'
      );
    }
  }
}

