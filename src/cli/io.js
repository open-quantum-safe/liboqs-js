/**
 * @fileoverview CLI input/output utilities
 */

import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import process from "node:process";
import { Buffer } from "node:buffer";

/**
 * Read input from various sources
 * @param {string} input - Input string (file path, hex:, base64:, -, or LIBOQS_* env var)
 * @param {string} inputFormat - Format override (hex|base64|auto)
 * @returns {Promise<Uint8Array>}
 */
export async function readInput(input, inputFormat = 'auto') {
  // Check for stdin
  if (input === '-') {
    return await readStdin();
  }

  // Check for env var reference (LIBOQS_* or $LIBOQS_*)
  const envVarName = input.startsWith('$') ? input.slice(1) : input;
  if (envVarName.startsWith('LIBOQS_')) {
    const envValue = process.env[envVarName];
    if (!envValue) {
      throw new Error(`Environment variable ${envVarName} is not set`);
    }
    input = envValue;
  }

  // Check for explicit encoding prefix
  if (input.startsWith('hex:')) {
    return hexToBytes(input.slice(4));
  }
  if (input.startsWith('base64:')) {
    return base64ToBytes(input.slice(7));
  }

  // Try to read as file
  if (existsSync(input)) {
    const buffer = await readFile(input);
    // Convert Buffer to Uint8Array for compatibility with algorithm validation
    return new Uint8Array(buffer);
  }

  // Auto-detect format or treat as raw string
  if (inputFormat === 'hex' || (inputFormat === 'auto' && /^[0-9a-fA-F]+$/.test(input))) {
    return hexToBytes(input);
  }
  if (inputFormat === 'base64' || (inputFormat === 'auto' && /^[A-Za-z0-9+/=]+$/.test(input))) {
    return base64ToBytes(input);
  }

  // Treat as raw string
  return new TextEncoder().encode(input);
}

/**
 * Read from stdin
 * @returns {Promise<Uint8Array>}
 */
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const buffer = Buffer.concat(chunks);
  // Convert Buffer to Uint8Array for compatibility with algorithm validation
  return new Uint8Array(buffer);
}

/**
 * Write output to file or stdout
 * @param {Uint8Array} data - Data to write
 * @param {string} format - Output format (hex|base64|raw)
 * @param {string|null} outputPath - Output file path or null for stdout
 */
export async function writeOutput(data, format = 'hex', outputPath = null) {
  let output;

  switch (format) {
    case 'hex':
      output = bytesToHex(data);
      break;
    case 'base64':
      output = bytesToBase64(data);
      break;
    case 'raw':
      output = data;
      break;
    default:
      throw new Error(`Unknown output format: ${format}`);
  }

  if (outputPath) {
    if (typeof output === 'string') {
      await writeFile(outputPath, output, 'utf8');
    } else {
      await writeFile(outputPath, output);
    }
  } else if (typeof output === 'string') {
    console.log(output);
  } else {
    process.stdout.write(output);
  }
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex) {
  const clean = hex.replaceAll(/\s/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBytes(base64) {
  const buffer = Buffer.from(base64, 'base64');
  // Convert Buffer to Uint8Array for compatibility with algorithm validation
  return new Uint8Array(buffer);
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert Uint8Array to base64 string
 */
function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}
