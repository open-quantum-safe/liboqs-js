/**
 * @fileoverview Signature command handlers
 */

import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { getSigFactory } from '../algorithms.js';
import { readInput, writeOutput } from '../io.js';
import process from "node:process";

export async function handleSigCommand(parsed) {
  const { subcommand, args, options } = parsed;

  switch (subcommand) {
    case 'keygen':
      return await sigKeygen(args[0], options);
    case 'sign':
      return await sigSign(args[0], args[1], args[2], options);
    case 'verify':
      return await sigVerify(args[0], args[1], args[2], args[3], options);
    default:
      throw new Error(`Unknown SIG subcommand: ${subcommand}`);
  }
}

async function sigKeygen(algorithm, options) {
  if (!algorithm) {
    throw new Error('Algorithm name required');
  }

  const factory = getSigFactory(algorithm);
  const sig = await factory();

  try {
    const { publicKey, secretKey } = sig.generateKeyPair();

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
    sig.destroy();
  }
}

async function sigSign(algorithm, messageInput, secretKeyInput, options) {
  if (!algorithm || !messageInput || !secretKeyInput) {
    throw new Error('Algorithm, message, and secret key required');
  }

  const factory = getSigFactory(algorithm);
  const sig = await factory();

  try {
    const message = await readInput(messageInput, options.inputFormat);
    const secretKey = await readInput(secretKeyInput, options.inputFormat);
    const signature = await sig.sign(message, secretKey);

    console.log('Signature:');
    await writeOutput(signature, options.format, options.output);
  } finally {
    sig.destroy();
  }
}

async function sigVerify(algorithm, messageInput, signatureInput, publicKeyInput, options) {
  if (!algorithm || !messageInput || !signatureInput || !publicKeyInput) {
    throw new Error('Algorithm, message, signature, and public key required');
  }

  const factory = getSigFactory(algorithm);
  const sig = await factory();

  try {
    const message = await readInput(messageInput, options.inputFormat);
    const signature = await readInput(signatureInput, options.inputFormat);
    const publicKey = await readInput(publicKeyInput, options.inputFormat);

    const isValid = sig.verify(message, signature, publicKey);

    if (isValid) {
      console.log('✓ Signature is valid');
      process.exit(0);
    } else {
      console.log('✗ Signature is invalid');
      process.exit(1);
    }
  } finally {
    sig.destroy();
  }
}
