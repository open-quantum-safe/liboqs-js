/**
 * @fileoverview TypeScript definitions for LibOQS error classes
 * @module @oqs/liboqs-js/errors
 */

/**
 * Base error class for all LibOQS errors
 */
export class LibOQSError extends Error {
  /**
   * Algorithm name (if applicable)
   */
  readonly algorithm?: string;

  /**
   * Operation name (if applicable)
   */
  readonly operation?: string;

  /**
   * @param message - Error message
   * @param algorithm - Algorithm name
   * @param operation - Operation name
   */
  constructor(message: string, algorithm?: string, operation?: string);
}

/**
 * Error thrown during algorithm initialization
 */
export class LibOQSInitError extends LibOQSError {
  /**
   * @param algorithm - Algorithm name
   * @param details - Additional error details
   */
  constructor(algorithm: string, details?: string);
}

/**
 * Error thrown during cryptographic operations
 */
export class LibOQSOperationError extends LibOQSError {
  /**
   * @param operation - Operation name (e.g., 'keypair', 'encaps', 'sign')
   * @param algorithm - Algorithm name
   * @param details - Additional error details
   */
  constructor(operation: string, algorithm: string, details?: string);
}

/**
 * Error thrown for validation failures
 */
export class LibOQSValidationError extends LibOQSError {
  /**
   * @param message - Error message
   * @param algorithm - Algorithm name
   */
  constructor(message: string, algorithm?: string);
}
