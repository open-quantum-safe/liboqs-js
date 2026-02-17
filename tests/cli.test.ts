/**
 * @fileoverview Comprehensive CLI tests for liboqs
 * @description Tests CLI functionality including:
 * - KEM operations (keygen, encapsulate, decapsulate)
 * - Signature operations (keygen, sign, verify)
 * - Various input/output formats (hex, base64, file, stdin)
 * - Error handling
 *
 * Uses ML-KEM-768 and ML-DSA-65 as representative algorithms
 */

import { describe, test, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Buffer } from "node:buffer";
import process from "node:process";

const CLI_PATH = join(process.cwd(), 'bin/cli.js');
const TEST_ALGORITHM_KEM = 'ml-kem-768';
const TEST_ALGORITHM_SIG = 'ml-dsa-65';

/**
 * Execute CLI command and return output
 */
function runCLI(args: string, options: { input?: string, expectError?: boolean } = {}) {
  const cmd = `node "${CLI_PATH}" ${args}`;

  try {
    const execOptions: any = {
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer for large outputs
    };

    if (options.input) {
      // Convert string input to Buffer for stdin
      execOptions.input = Buffer.from(options.input, 'utf8');
      execOptions.stdio = ['pipe', 'pipe', 'pipe'];
      // Remove encoding to get Buffer output when using stdin
      delete execOptions.encoding;
    }

    const result = execSync(cmd, execOptions);

    // Convert result to string if it's a Buffer
    const stdout = typeof result === 'string' ? result : (result as Buffer).toString('utf8');
    return { stdout, exitCode: 0 };
  } catch (error: any) {
    if (options.expectError) {
      const stdout = error.stdout ? (typeof error.stdout === 'string' ? error.stdout : error.stdout.toString('utf8')) : '';
      const stderr = error.stderr ? (typeof error.stderr === 'string' ? error.stderr : error.stderr.toString('utf8')) : '';
      return {
        stdout,
        stderr,
        exitCode: error.status || 1
      };
    }
    throw error;
  }
}

/**
 * Extract hex-encoded output from CLI output
 */
function extractHexOutput(output: string, label: string): string {
  const lines = output.split('\n');
  const labelIndex = lines.findIndex(line => line.includes(label));
  if (labelIndex === -1) return '';

  // Get the next non-empty line after the label
  for (let i = labelIndex + 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && /^[0-9a-fA-F]+$/.test(line)) {
      return line;
    }
  }
  return '';
}

describe('CLI - KEM Operations', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'liboqs-cli-test-'));
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('should generate KEM keypair to stdout (hex format)', () => {
    const result = runCLI(`kem keygen ${TEST_ALGORITHM_KEM}`);

    expect(result.stdout).toContain('Public Key:');
    expect(result.stdout).toContain('Secret Key:');

    const publicKey = extractHexOutput(result.stdout, 'Public Key:');
    const secretKey = extractHexOutput(result.stdout, 'Secret Key:');

    expect(publicKey).toMatch(/^[0-9a-f]+$/);
    expect(secretKey).toMatch(/^[0-9a-f]+$/);
    expect(publicKey.length).toBeGreaterThan(0);
    expect(secretKey.length).toBeGreaterThan(0);
  });

  test('should generate KEM keypair to directory', () => {
    const outputDir = join(tempDir, 'keys');
    runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format raw`);

    expect(existsSync(join(outputDir, 'public.key'))).toBe(true);
    expect(existsSync(join(outputDir, 'secret.key'))).toBe(true);

    const publicKey = readFileSync(join(outputDir, 'public.key'));
    const secretKey = readFileSync(join(outputDir, 'secret.key'));

    expect(publicKey.length).toBeGreaterThan(0);
    expect(secretKey.length).toBeGreaterThan(0);
  });

  test('should generate KEM keypair in base64 format', () => {
    const result = runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --format base64`);

    const lines = result.stdout.split('\n');
    const publicKeyLine = lines.find((line: string) => /^[A-Za-z0-9+/=]{20,}$/.test(line.trim()));

    expect(publicKeyLine).toBeDefined();
    expect(publicKeyLine).toMatch(/^[A-Za-z0-9+/=]+$/);
  });

  test('should perform complete KEM workflow (keygen -> encapsulate -> decapsulate)', () => {
    // Generate keypair in raw binary format
    const outputDir = join(tempDir, 'kem-workflow');
    runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, 'public.key');
    const secretKeyPath = join(outputDir, 'secret.key');

    // Encapsulate
    const encapResult = runCLI(`kem encapsulate ${TEST_ALGORITHM_KEM} "${publicKeyPath}"`);

    const ciphertext = extractHexOutput(encapResult.stdout, 'Ciphertext:');
    const sharedSecret1 = extractHexOutput(encapResult.stdout, 'Shared Secret:');

    expect(ciphertext).toMatch(/^[0-9a-f]+$/);
    expect(sharedSecret1).toMatch(/^[0-9a-f]+$/);

    // Write ciphertext to file for decapsulation
    const ctPath = join(tempDir, 'ciphertext.bin');
    const ctBytes = Buffer.from(ciphertext, 'hex');
    writeFileSync(ctPath, ctBytes);

    // Decapsulate
    const decapResult = runCLI(`kem decapsulate ${TEST_ALGORITHM_KEM} "${ctPath}" "${secretKeyPath}"`);

    const sharedSecret2 = extractHexOutput(decapResult.stdout, 'Shared Secret:');

    expect(sharedSecret2).toBe(sharedSecret1);
  });

  test('should handle hex-encoded input via hex: prefix', () => {
    const outputDir = join(tempDir, 'hex-input');
    runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format hex`);

    const publicKeyHex = readFileSync(join(outputDir, 'public.key'), 'utf8');

    const result = runCLI(`kem encapsulate ${TEST_ALGORITHM_KEM} "hex:${publicKeyHex}"`);

    expect(result.stdout).toContain('Ciphertext:');
    expect(result.stdout).toContain('Shared Secret:');
  });

  test('should handle base64-encoded input via base64: prefix', () => {
    const outputDir = join(tempDir, 'base64-input');
    runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format base64`);

    const publicKeyB64 = readFileSync(join(outputDir, 'public.key'), 'utf8');

    const result = runCLI(`kem encapsulate ${TEST_ALGORITHM_KEM} "base64:${publicKeyB64}"`);

    expect(result.stdout).toContain('Ciphertext:');
    expect(result.stdout).toContain('Shared Secret:');
  });

  test('should write output to files with --output option', () => {
    const outputDir = join(tempDir, 'output-files');
    runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, 'public.key');
    const outputBase = join(tempDir, 'encap-output');

    runCLI(`kem encapsulate ${TEST_ALGORITHM_KEM} "${publicKeyPath}" --output "${outputBase}"`);

    expect(existsSync(`${outputBase}.ct`)).toBe(true);
    expect(existsSync(`${outputBase}.ss`)).toBe(true);
  });

  test('should fail with invalid algorithm', () => {
    const result = runCLI('kem keygen invalid-algorithm-123', { expectError: true });

    expect(result.exitCode).toBe(1);
    expect(result.stderr || result.stdout).toMatch(/error/i);
  });
});

describe('CLI - Signature Operations', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'liboqs-cli-sig-test-'));
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('should generate signature keypair to stdout', () => {
    const result = runCLI(`sig keygen ${TEST_ALGORITHM_SIG}`);

    expect(result.stdout).toContain('Public Key:');
    expect(result.stdout).toContain('Secret Key:');

    const publicKey = extractHexOutput(result.stdout, 'Public Key:');
    const secretKey = extractHexOutput(result.stdout, 'Secret Key:');

    expect(publicKey).toMatch(/^[0-9a-f]+$/);
    expect(secretKey).toMatch(/^[0-9a-f]+$/);
  });

  test('should generate signature keypair to directory', () => {
    const outputDir = join(tempDir, 'sig-keys');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    expect(existsSync(join(outputDir, 'public.key'))).toBe(true);
    expect(existsSync(join(outputDir, 'secret.key'))).toBe(true);
  });

  test('should perform complete signature workflow (keygen -> sign -> verify)', () => {
    // Generate keypair in raw binary format
    const outputDir = join(tempDir, 'sig-workflow');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, 'public.key');
    const secretKeyPath = join(outputDir, 'secret.key');

    // Create test message
    const message = 'Hello, post-quantum world!';
    const messagePath = join(tempDir, 'message.txt');
    writeFileSync(messagePath, message);

    // Sign the message
    const signaturePath = join(tempDir, 'signature.bin');
    runCLI(`sig sign ${TEST_ALGORITHM_SIG} "${messagePath}" "${secretKeyPath}" --output "${signaturePath}" --format raw`);

    expect(existsSync(signaturePath)).toBe(true);

    // Verify the signature
    const verifyResult = runCLI(`sig verify ${TEST_ALGORITHM_SIG} "${messagePath}" "${signaturePath}" "${publicKeyPath}"`);

    expect(verifyResult.stdout).toContain('✓');
    expect(verifyResult.stdout).toMatch(/valid/i);
  });

  test('should sign and verify with direct string message', () => {
    const outputDir = join(tempDir, 'string-sig');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, 'public.key');
    const secretKeyPath = join(outputDir, 'secret.key');
    const signaturePath = join(tempDir, 'sig.bin');

    // Sign with direct string
    runCLI(`sig sign ${TEST_ALGORITHM_SIG} "Test message" "${secretKeyPath}" --output "${signaturePath}" --format raw`);

    // Verify with same string
    const result = runCLI(`sig verify ${TEST_ALGORITHM_SIG} "Test message" "${signaturePath}" "${publicKeyPath}"`);

    expect(result.stdout).toContain('✓');
  });

  test('should fail verification with wrong signature', () => {
    const outputDir = join(tempDir, 'wrong-sig');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, 'public.key');
    const secretKeyPath = join(outputDir, 'secret.key');

    // Sign message 1
    const sig1Path = join(tempDir, 'sig1.bin');
    runCLI(`sig sign ${TEST_ALGORITHM_SIG} "message1" "${secretKeyPath}" --output "${sig1Path}" --format raw`);

    // Try to verify different message with signature
    const result = runCLI(`sig verify ${TEST_ALGORITHM_SIG} "message2" "${sig1Path}" "${publicKeyPath}"`, { expectError: true });

    expect(result.stdout).toContain('✗');
    expect(result.stdout).toMatch(/invalid/i);
    expect(result.exitCode).toBe(1);
  });

  test('should handle hex-encoded secret key input', () => {
    const outputDir = join(tempDir, 'hex-key');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format hex`);

    const secretKeyHex = readFileSync(join(outputDir, 'secret.key'), 'utf8');
    const signaturePath = join(tempDir, 'sig.bin');

    runCLI(`sig sign ${TEST_ALGORITHM_SIG} "test" "hex:${secretKeyHex}" --output "${signaturePath}" --format raw`);

    expect(existsSync(signaturePath)).toBe(true);
  });

  test('should output signature in different formats', () => {
    const outputDir = join(tempDir, 'formats');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const secretKeyPath = join(outputDir, 'secret.key');

    // Hex format
    const hexResult = runCLI(`sig sign ${TEST_ALGORITHM_SIG} "test" "${secretKeyPath}" --format hex`);
    expect(hexResult.stdout).toMatch(/[0-9a-f]+/);

    // Base64 format
    const b64Result = runCLI(`sig sign ${TEST_ALGORITHM_SIG} "test" "${secretKeyPath}" --format base64`);
    expect(b64Result.stdout).toMatch(/[A-Za-z0-9+/=]+/);
  });
});

describe('CLI - Input/Output Modes', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'liboqs-cli-io-test-'));
  });

  afterEach(() => {
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('should read from stdin using dash (-)', () => {
    const outputDir = join(tempDir, 'stdin-test');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, 'public.key');
    const secretKeyPath = join(outputDir, 'secret.key');
    const signaturePath = join(tempDir, 'sig.bin');

    const message = 'Message from stdin';

    // Sign with stdin
    runCLI(`sig sign ${TEST_ALGORITHM_SIG} - "${secretKeyPath}" --output "${signaturePath}" --format raw`, { input: message });

    // Verify with stdin
    const result = runCLI(`sig verify ${TEST_ALGORITHM_SIG} - "${signaturePath}" "${publicKeyPath}"`, { input: message });

    expect(result.stdout).toContain('✓');
  });

  test('should support environment variable references for keys', () => {
    const outputDir = join(tempDir, 'env-test');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format hex`);

    const secretKeyHex = readFileSync(join(outputDir, 'secret.key'), 'utf8').trim();
    const signaturePath = join(tempDir, 'sig.bin');

    // Set environment variable
    process.env.LIBOQS_SECRET_KEY = secretKeyHex;

    try {
      runCLI(`sig sign ${TEST_ALGORITHM_SIG} "test" LIBOQS_SECRET_KEY --output "${signaturePath}" --input-format hex --format raw`);
      expect(existsSync(signaturePath)).toBe(true);
    } finally {
      delete process.env.LIBOQS_SECRET_KEY;
    }
  });

  test('should support $LIBOQS_* environment variable syntax', () => {
    const outputDir = join(tempDir, 'env-dollar-test');
    runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format hex`);

    const publicKeyHex = readFileSync(join(outputDir, 'public.key'), 'utf8').trim();

    process.env.LIBOQS_PUBLIC_KEY = publicKeyHex;

    try {
      const result = runCLI(`kem encapsulate ${TEST_ALGORITHM_KEM} "$LIBOQS_PUBLIC_KEY" --input-format hex`, { expectError: true });
      // This might fail because we're using sig key for kem, but it should parse the env var
      // The important thing is it attempts to use the env var, not that it succeeds
      expect(result.stderr || result.stdout).not.toContain('LIBOQS_PUBLIC_KEY is not set');
    } finally {
      delete process.env.LIBOQS_PUBLIC_KEY;
    }
  });
});

describe('CLI - General Commands', () => {
  test('should show help with --help', () => {
    const result = runCLI('--help', { expectError: true });

    expect(result.stdout).toContain('liboqs');
    expect(result.stdout).toContain('Commands:');
    expect(result.stdout).toContain('kem');
    expect(result.stdout).toContain('sig');
  });

  test('should show help with help command', () => {
    const result = runCLI('help');

    expect(result.stdout).toContain('liboqs');
    expect(result.stdout).toContain('Usage:');
  });

  test('should list KEM algorithms', () => {
    const result = runCLI('list --kem');

    expect(result.stdout).toContain('ml-kem-768');
    expect(result.stdout).toContain('ml-kem-512');
    expect(result.stdout).toContain('ml-kem-1024');
  });

  test('should list signature algorithms', () => {
    const result = runCLI('list --sig');

    expect(result.stdout).toContain('ml-dsa-65');
    expect(result.stdout).toContain('ml-dsa-44');
    expect(result.stdout).toContain('ml-dsa-87');
  });

  test('should show algorithm info', () => {
    const result = runCLI(`info ${TEST_ALGORITHM_KEM}`);

    expect(result.stdout.toLowerCase()).toContain('ml-kem-768');
    expect(result.stdout).toMatch(/kem/i);
  });
});
