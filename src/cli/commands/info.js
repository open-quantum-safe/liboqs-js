/**
 * @fileoverview Info command handler
 */

import { getAlgorithmInfo } from '../algorithms.js';

export function handleInfoCommand(parsed) {
  const { args } = parsed;
  const algorithm = args[0];

  if (!algorithm) {
    throw new Error('Algorithm name required');
  }

  const info = getAlgorithmInfo(algorithm);

  console.log(`\nAlgorithm: ${info.name}`);
  console.log(`Type: ${info.type.toUpperCase()}`);
  console.log(`Identifier: ${info.identifier}`);
  console.log(`Security Level: ${info.securityLevel}`);
  console.log(`Standardized: ${info.standardized ? 'Yes' : 'No'}`);
  console.log(`\nDescription: ${info.description}`);
  console.log(`\nKey Sizes:`);
  console.log(`  Public Key:  ${info.keySize.publicKey.toLocaleString()} bytes`);
  console.log(`  Secret Key:  ${info.keySize.secretKey.toLocaleString()} bytes`);

  if (info.type === 'kem') {
    console.log(`  Ciphertext:  ${info.keySize.ciphertext.toLocaleString()} bytes`);
    console.log(`  Shared Secret: ${info.keySize.sharedSecret.toLocaleString()} bytes`);
  } else {
    console.log(`  Signature (max): ${info.keySize.signature.toLocaleString()} bytes`);
  }

  console.log('');
}
