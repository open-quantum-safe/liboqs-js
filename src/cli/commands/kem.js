/**
 * @fileoverview KEM command handlers
 */

import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { getKemFactory } from '../algorithms.js';
import { readInput, writeOutput } from '../io.js';

export async function handleKemCommand(parsed) {
  const { subcommand, args, options } = parsed;

  switch (subcommand) {
    case 'keygen':
      return await kemKeygen(args[0], options);
    case 'encapsulate':
      return await kemEncapsulate(args[0], args[1], options);
    case 'decapsulate':
      return await kemDecapsulate(args[0], args[1], args[2], options);
    default:
      throw new Error(`Unknown KEM subcommand: ${subcommand}`);
  }
}

async function kemKeygen(algorithm, options) {
  if (!algorithm) {
    throw new Error('Algorithm name required');
  }

  const factory = getKemFactory(algorithm);
  const kem = await factory();

  try {
    const { publicKey, secretKey } = kem.generateKeyPair();

    if (options.outputDir) {
      await mkdir(options.outputDir, { recursive: true });
      await writeOutput(publicKey, options.format, join(options.outputDir, 'public.key'));
      await writeOutput(secretKey, options.format, join(options.outputDir, 'secret.key'));
      console.log(`Keypair saved to ${options.outputDir}/`);
    } else {
      console.log('Public Key:');
      await writeOutput(publicKey, options.format, null);
      console.log('\nSecret Key:');
      await writeOutput(secretKey, options.format, null);
    }
  } finally {
    kem.destroy();
  }
}

async function kemEncapsulate(algorithm, publicKeyInput, options) {
  if (!algorithm || !publicKeyInput) {
    throw new Error('Algorithm and public key required');
  }

  const factory = getKemFactory(algorithm);
  const kem = await factory();

  try {
    const publicKey = await readInput(publicKeyInput, options.inputFormat);
    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);

    console.log('Ciphertext:');
    await writeOutput(ciphertext, options.format, options.output ? options.output + '.ct' : null);
    console.log('\nShared Secret:');
    await writeOutput(sharedSecret, options.format, options.output ? options.output + '.ss' : null);
  } finally {
    kem.destroy();
  }
}

async function kemDecapsulate(algorithm, ciphertextInput, secretKeyInput, options) {
  if (!algorithm || !ciphertextInput || !secretKeyInput) {
    throw new Error('Algorithm, ciphertext, and secret key required');
  }

  const factory = getKemFactory(algorithm);
  const kem = await factory();

  try {
    const ciphertext = await readInput(ciphertextInput, options.inputFormat);
    const secretKey = await readInput(secretKeyInput, options.inputFormat);
    const sharedSecret = kem.decapsulate(ciphertext, secretKey);

    console.log('Shared Secret:');
    await writeOutput(sharedSecret, options.format, options.output);
  } finally {
    kem.destroy();
  }
}
