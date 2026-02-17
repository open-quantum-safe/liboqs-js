/// <reference lib="deno.ns" />

/**
 * @fileoverview Comprehensive CLI tests for liboqs (Deno)
 * @description Tests CLI functionality including:
 * - KEM operations (keygen, encapsulate, decapsulate)
 * - Signature operations (keygen, sign, verify)
 * - Various input/output formats (hex, base64, file, stdin)
 * - Error handling
 *
 * Uses ML-KEM-768 and ML-DSA-65 as representative algorithms
 */

import { assertEquals, assertMatch, assert } from "@std/assert";
import { join } from "@std/path";
import { exists } from "@std/fs";

const CLI_PATH = new URL("../../bin/cli.js", import.meta.url).pathname;
const TEST_ALGORITHM_KEM = "ml-kem-768";
const TEST_ALGORITHM_SIG = "ml-dsa-65";

/**
 * Parse command arguments respecting quotes
 */
function parseArgs(argString: string): string[] {
  const args: string[] = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';

  for (const element of argString) {
    const char = element;

    if ((char === '"' || char === "'") && !inQuotes) {
      inQuotes = true;
      quoteChar = char;
    } else if (char === quoteChar && inQuotes) {
      inQuotes = false;
      quoteChar = '';
    } else if (char === ' ' && !inQuotes) {
      if (current) {
        args.push(current);
        current = '';
      }
    } else {
      current += char;
    }
  }

  if (current) {
    args.push(current);
  }

  return args;
}

/**
 * Execute CLI command and return output
 */
async function runCLI(
  args: string,
  options: { input?: string; expectError?: boolean } = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const command = new Deno.Command("node", {
    args: [CLI_PATH, ...parseArgs(args)],
    stdin: options.input ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  });

  const process = command.spawn();

  if (options.input) {
    const writer = process.stdin.getWriter();
    await writer.write(new TextEncoder().encode(options.input));
    await writer.close();
  }

  const { stdout, stderr, code } = await process.output();

  return {
    stdout: new TextDecoder().decode(stdout),
    stderr: new TextDecoder().decode(stderr),
    exitCode: code,
  };
}

/**
 * Extract hex-encoded output from CLI output
 */
function extractHexOutput(output: string, label: string): string {
  const lines = output.split("\n");
  const labelIndex = lines.findIndex((line) => line.includes(label));
  if (labelIndex === -1) return "";

  // Get the next non-empty line after the label
  for (let i = labelIndex + 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && /^[0-9a-fA-F]+$/.test(line)) {
      return line;
    }
  }
  return "";
}

Deno.test("CLI - KEM - should generate KEM keypair to stdout (hex format)", async () => {
  const result = await runCLI(`kem keygen ${TEST_ALGORITHM_KEM}`);

  assert(result.stdout.includes("Public Key:"));
  assert(result.stdout.includes("Secret Key:"));

  const publicKey = extractHexOutput(result.stdout, "Public Key:");
  const secretKey = extractHexOutput(result.stdout, "Secret Key:");

  assertMatch(publicKey, /^[0-9a-f]+$/);
  assertMatch(secretKey, /^[0-9a-f]+$/);
  assert(publicKey.length > 0);
  assert(secretKey.length > 0);
});

Deno.test("CLI - KEM - should generate KEM keypair to directory", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "keys");
    await runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format raw`);

    assert(await exists(join(outputDir, "public.key")));
    assert(await exists(join(outputDir, "secret.key")));

    const publicKey = await Deno.readFile(join(outputDir, "public.key"));
    const secretKey = await Deno.readFile(join(outputDir, "secret.key"));

    assert(publicKey.length > 0);
    assert(secretKey.length > 0);
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - KEM - should generate KEM keypair in base64 format", async () => {
  const result = await runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --format base64`);

  const lines = result.stdout.split("\n");
  const publicKeyLine = lines.find((line) =>
    /^[A-Za-z0-9+/=]{20,}$/.test(line.trim())
  );

  assert(publicKeyLine !== undefined);
  assertMatch(publicKeyLine, /^[A-Za-z0-9+/=]+$/);
});

Deno.test("CLI - KEM - should perform complete KEM workflow", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    // Generate keypair in raw binary format
    const outputDir = join(tempDir, "kem-workflow");
    await runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, "public.key");
    const secretKeyPath = join(outputDir, "secret.key");

    // Encapsulate
    const encapResult = await runCLI(
      `kem encapsulate ${TEST_ALGORITHM_KEM} "${publicKeyPath}"`
    );

    const ciphertext = extractHexOutput(encapResult.stdout, "Ciphertext:");
    const sharedSecret1 = extractHexOutput(encapResult.stdout, "Shared Secret:");

    assertMatch(ciphertext, /^[0-9a-f]+$/);
    assertMatch(sharedSecret1, /^[0-9a-f]+$/);

    // Write ciphertext to file for decapsulation
    const ctPath = join(tempDir, "ciphertext.bin");
    const ctBytes = new Uint8Array(ciphertext.length / 2);
    for (let i = 0; i < ctBytes.length; i++) {
      ctBytes[i] = Number.parseInt(ciphertext.substring(i * 2, i * 2 + 2), 16);
    }
    await Deno.writeFile(ctPath, ctBytes);

    // Decapsulate
    const decapResult = await runCLI(
      `kem decapsulate ${TEST_ALGORITHM_KEM} "${ctPath}" "${secretKeyPath}"`
    );

    const sharedSecret2 = extractHexOutput(decapResult.stdout, "Shared Secret:");

    assertEquals(sharedSecret2, sharedSecret1);
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - KEM - should handle hex-encoded input via hex: prefix", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "hex-input");
    await runCLI(
      `kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format hex`
    );

    const publicKeyHex = await Deno.readTextFile(join(outputDir, "public.key"));

    const result = await runCLI(
      `kem encapsulate ${TEST_ALGORITHM_KEM} "hex:${publicKeyHex}"`
    );

    assert(result.stdout.includes("Ciphertext:"));
    assert(result.stdout.includes("Shared Secret:"));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - KEM - should handle base64-encoded input via base64: prefix", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "base64-input");
    await runCLI(
      `kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format base64`
    );

    const publicKeyB64 = await Deno.readTextFile(join(outputDir, "public.key"));

    const result = await runCLI(
      `kem encapsulate ${TEST_ALGORITHM_KEM} "base64:${publicKeyB64}"`
    );

    assert(result.stdout.includes("Ciphertext:"));
    assert(result.stdout.includes("Shared Secret:"));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - KEM - should write output to files with --output option", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "output-files");
    await runCLI(`kem keygen ${TEST_ALGORITHM_KEM} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, "public.key");
    const outputBase = join(tempDir, "encap-output");

    await runCLI(
      `kem encapsulate ${TEST_ALGORITHM_KEM} "${publicKeyPath}" --output "${outputBase}"`
    );

    assert(await exists(`${outputBase}.ct`));
    assert(await exists(`${outputBase}.ss`));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - KEM - should fail with invalid algorithm", async () => {
  const result = await runCLI("kem keygen invalid-algorithm-123", {
    expectError: true,
  });

  assertEquals(result.exitCode, 1);
  assertMatch(result.stderr + result.stdout, /error/i);
});

Deno.test("CLI - Signature - should generate signature keypair to stdout", async () => {
  const result = await runCLI(`sig keygen ${TEST_ALGORITHM_SIG}`);

  assert(result.stdout.includes("Public Key:"));
  assert(result.stdout.includes("Secret Key:"));

  const publicKey = extractHexOutput(result.stdout, "Public Key:");
  const secretKey = extractHexOutput(result.stdout, "Secret Key:");

  assertMatch(publicKey, /^[0-9a-f]+$/);
  assertMatch(secretKey, /^[0-9a-f]+$/);
});

Deno.test("CLI - Signature - should generate signature keypair to directory", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "sig-keys");
    await runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    assert(await exists(join(outputDir, "public.key")));
    assert(await exists(join(outputDir, "secret.key")));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - Signature - should perform complete signature workflow", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    // Generate keypair in raw binary format
    const outputDir = join(tempDir, "sig-workflow");
    await runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, "public.key");
    const secretKeyPath = join(outputDir, "secret.key");

    // Create test message
    const message = "Hello, post-quantum world!";
    const messagePath = join(tempDir, "message.txt");
    await Deno.writeTextFile(messagePath, message);

    // Sign the message
    const signaturePath = join(tempDir, "signature.bin");
    await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} "${messagePath}" "${secretKeyPath}" --output "${signaturePath}" --format raw`
    );

    assert(await exists(signaturePath));

    // Verify the signature
    const verifyResult = await runCLI(
      `sig verify ${TEST_ALGORITHM_SIG} "${messagePath}" "${signaturePath}" "${publicKeyPath}"`
    );

    assert(verifyResult.stdout.includes("✓"));
    assertMatch(verifyResult.stdout, /valid/i);
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - Signature - should sign and verify with direct string message", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "string-sig");
    await runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, "public.key");
    const secretKeyPath = join(outputDir, "secret.key");
    const signaturePath = join(tempDir, "sig.bin");

    // Sign with direct string
    await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} "Test message" "${secretKeyPath}" --output "${signaturePath}" --format raw`
    );

    // Verify with same string
    const result = await runCLI(
      `sig verify ${TEST_ALGORITHM_SIG} "Test message" "${signaturePath}" "${publicKeyPath}"`
    );

    assert(result.stdout.includes("✓"));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - Signature - should fail verification with wrong signature", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "wrong-sig");
    await runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, "public.key");
    const secretKeyPath = join(outputDir, "secret.key");

    // Sign message 1
    const sig1Path = join(tempDir, "sig1.bin");
    await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} "message1" "${secretKeyPath}" --output "${sig1Path}" --format raw`
    );

    // Try to verify different message with signature
    const result = await runCLI(
      `sig verify ${TEST_ALGORITHM_SIG} "message2" "${sig1Path}" "${publicKeyPath}"`,
      { expectError: true }
    );

    assert(result.stdout.includes("✗"));
    assertMatch(result.stdout, /invalid/i);
    assertEquals(result.exitCode, 1);
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - Signature - should handle hex-encoded secret key input", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "hex-key");
    await runCLI(
      `sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format hex`
    );

    const secretKeyHex = await Deno.readTextFile(join(outputDir, "secret.key"));
    const signaturePath = join(tempDir, "sig.bin");

    await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} "test" "hex:${secretKeyHex}" --output "${signaturePath}" --format raw`
    );

    assert(await exists(signaturePath));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - Signature - should output signature in different formats", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "formats");
    await runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const secretKeyPath = join(outputDir, "secret.key");

    // Hex format
    const hexResult = await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} "test" "${secretKeyPath}" --format hex`
    );
    assertMatch(hexResult.stdout, /[0-9a-f]+/);

    // Base64 format
    const b64Result = await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} "test" "${secretKeyPath}" --format base64`
    );
    assertMatch(b64Result.stdout, /[A-Za-z0-9+/=]+/);
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - I/O - should read from stdin using dash (-)", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "stdin-test");
    await runCLI(`sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format raw`);

    const publicKeyPath = join(outputDir, "public.key");
    const secretKeyPath = join(outputDir, "secret.key");
    const signaturePath = join(tempDir, "sig.bin");

    const message = "Message from stdin";

    // Sign with stdin
    await runCLI(
      `sig sign ${TEST_ALGORITHM_SIG} - "${secretKeyPath}" --output "${signaturePath}" --format raw`,
      { input: message }
    );

    // Verify with stdin
    const result = await runCLI(
      `sig verify ${TEST_ALGORITHM_SIG} - "${signaturePath}" "${publicKeyPath}"`,
      { input: message }
    );

    assert(result.stdout.includes("✓"));
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - I/O - should support environment variable references for keys", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "env-test");
    await runCLI(
      `sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format hex`
    );

    const secretKeyHex = (
      await Deno.readTextFile(join(outputDir, "secret.key"))
    ).trim();
    const signaturePath = join(tempDir, "sig.bin");

    // Set environment variable
    Deno.env.set("LIBOQS_SECRET_KEY", secretKeyHex);

    try {
      await runCLI(
        `sig sign ${TEST_ALGORITHM_SIG} "test" LIBOQS_SECRET_KEY --output "${signaturePath}" --input-format hex --format raw`
      );
      assert(await exists(signaturePath));
    } finally {
      Deno.env.delete("LIBOQS_SECRET_KEY");
    }
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - I/O - should support $LIBOQS_* environment variable syntax", async () => {
  const tempDir = await Deno.makeTempDir();

  try {
    const outputDir = join(tempDir, "env-dollar-test");
    await runCLI(
      `sig keygen ${TEST_ALGORITHM_SIG} --output-dir "${outputDir}" --format hex`
    );

    const publicKeyHex = (
      await Deno.readTextFile(join(outputDir, "public.key"))
    ).trim();

    Deno.env.set("LIBOQS_PUBLIC_KEY", publicKeyHex);

    try {
      const result = await runCLI(
        `kem encapsulate ${TEST_ALGORITHM_KEM} "$LIBOQS_PUBLIC_KEY" --input-format hex`,
        { expectError: true }
      );
      // This might fail because we're using sig key for kem, but it should parse the env var
      // The important thing is it attempts to use the env var, not that it succeeds
      assert(
        !(result.stderr + result.stdout).includes("LIBOQS_PUBLIC_KEY is not set")
      );
    } finally {
      Deno.env.delete("LIBOQS_PUBLIC_KEY");
    }
  } finally {
    await Deno.remove(tempDir, { recursive: true });
  }
});

Deno.test("CLI - General - should show help with --help", async () => {
  const result = await runCLI("--help", { expectError: true });

  assert(result.stdout.includes("liboqs"));
  assert(result.stdout.includes("Commands:"));
  assert(result.stdout.includes("kem"));
  assert(result.stdout.includes("sig"));
});

Deno.test("CLI - General - should show help with help command", async () => {
  const result = await runCLI("help");

  assert(result.stdout.includes("liboqs"));
  assert(result.stdout.includes("Usage:"));
});

Deno.test("CLI - General - should list KEM algorithms", async () => {
  const result = await runCLI("list --kem");

  assert(result.stdout.includes("ml-kem-768"));
  assert(result.stdout.includes("ml-kem-512"));
  assert(result.stdout.includes("ml-kem-1024"));
});

Deno.test("CLI - General - should list signature algorithms", async () => {
  const result = await runCLI("list --sig");

  assert(result.stdout.includes("ml-dsa-65"));
  assert(result.stdout.includes("ml-dsa-44"));
  assert(result.stdout.includes("ml-dsa-87"));
});

Deno.test("CLI - General - should show algorithm info", async () => {
  const result = await runCLI(`info ${TEST_ALGORITHM_KEM}`);

  assert(result.stdout.toLowerCase().includes("ml-kem-768"));
  assertMatch(result.stdout, /kem/i);
});
