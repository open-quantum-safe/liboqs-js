/**
 * @fileoverview List command handler
 */

import { KEM_ALGORITHMS, SIG_ALGORITHMS } from '../algorithms.js';

export function handleListCommand(parsed) {
  const { options } = parsed;

  if (options.kem) {
    console.log('KEM Algorithms:');
    Object.keys(KEM_ALGORITHMS).sort((a, b) => a.localeCompare(b)).forEach(alg => {
      console.log(`  ${alg}`);
    });
  } else if (options.sig) {
    console.log('Signature Algorithms:');
    Object.keys(SIG_ALGORITHMS).sort((a, b) => a.localeCompare(b)).forEach(alg => {
      console.log(`  ${alg}`);
    });
  } else {
    console.log('KEM Algorithms:');
    Object.keys(KEM_ALGORITHMS).sort((a, b) => a.localeCompare(b)).forEach(alg => {
      console.log(`  ${alg}`);
    });
    console.log('\nSignature Algorithms:');
    Object.keys(SIG_ALGORITHMS).sort((a, b) => a.localeCompare(b)).forEach(alg => {
      console.log(`  ${alg}`);
    });
  }
}
