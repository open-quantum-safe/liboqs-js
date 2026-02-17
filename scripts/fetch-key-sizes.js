#!/usr/bin/env node

/**
 * @fileoverview Fetch key sizes from existing algorithm files and update algorithms.json
 * @description This script reads existing algorithm implementations to extract key sizes
 * and updates the algorithms.json with this information.
 */

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from "node:process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

const algorithmsPath = join(rootDir, 'algorithms.json');
const algorithms = JSON.parse(readFileSync(algorithmsPath, 'utf8'));

/**
 * Extract key size from algorithm file
 */
function extractKeySizes(filePath) {
  try {
    const content = readFileSync(filePath, 'utf8');

    // Look for keySize object in the INFO constant
    const match = content.match(/keySize:\s*{([^}]+)}/);
    if (!match) return null;

    const keySizeStr = match[1];
    const sizes = {};

    // Extract individual sizes
    const publicKeyMatch = keySizeStr.match(/publicKey:\s*(\d+)/);
    const secretKeyMatch = keySizeStr.match(/secretKey:\s*(\d+)/);
    const ciphertextMatch = keySizeStr.match(/ciphertext:\s*(\d+)/);
    const sharedSecretMatch = keySizeStr.match(/sharedSecret:\s*(\d+)/);
    const signatureMatch = keySizeStr.match(/signature:\s*(\d+)/);

    if (publicKeyMatch) sizes.publicKey = Number.parseInt(publicKeyMatch[1]);
    if (secretKeyMatch) sizes.secretKey = Number.parseInt(secretKeyMatch[1]);
    if (ciphertextMatch) sizes.ciphertext = Number.parseInt(ciphertextMatch[1]);
    if (sharedSecretMatch) sizes.sharedSecret = Number.parseInt(sharedSecretMatch[1]);
    if (signatureMatch) sizes.signature = Number.parseInt(signatureMatch[1]);

    return Object.keys(sizes).length > 0 ? sizes : null;
  } catch (err) {
    return null;
  }
}

/**
 * Scan all algorithm files and extract key sizes
 */
function scanAlgorithmFiles() {
  const keySizeMap = {};
  const algDir = join(rootDir, 'src', 'algorithms');

  function scanDir(dir) {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          scanDir(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.js')) {
          const slug = entry.name.replace('.js', '');
          const sizes = extractKeySizes(fullPath);

          if (sizes) {
            keySizeMap[slug] = sizes;
            console.log(`✓ ${slug}:`, sizes);
          }
        }
      }
    } catch (err) {
      // Directory might not exist yet
    }
  }

  scanDir(algDir);
  return keySizeMap;
}

/**
 * Update algorithms.json with key sizes
 */
function updateAlgorithmsJson(keySizeMap) {
  let updated = 0;
  let added = 0;

  for (const [type, families] of Object.entries(algorithms)) {
    for (const [family, algos] of Object.entries(families)) {
      for (const [name, data] of Object.entries(algos)) {
        const slug = data.slug;

        if (keySizeMap[slug]) {
          if (data.keySize) {
            // Update existing
            algorithms[type][family][name].keySize = keySizeMap[slug];
            updated++;
          } else {
            // Add new
            algorithms[type][family][name].keySize = keySizeMap[slug];
            added++;
          }
        }
      }
    }
  }

  writeFileSync(algorithmsPath, JSON.stringify(algorithms, null, 2) + '\n', 'utf8');
  console.log(`\n✓ Updated algorithms.json:`);
  console.log(`  - ${added} key sizes added`);
  console.log(`  - ${updated} key sizes updated`);
}

/**
 * Main function
 */
function main() {
  console.log('Scanning algorithm files for key sizes...\n');
  const keySizeMap = scanAlgorithmFiles();

  if (Object.keys(keySizeMap).length === 0) {
    console.log('\n⚠ No key sizes found. Make sure algorithm files exist.');
    process.exit(1);
  }

  console.log(`\nFound ${Object.keys(keySizeMap).length} algorithms with key sizes`);
  console.log('\nUpdating algorithms.json...');
  updateAlgorithmsJson(keySizeMap);
}

main();
