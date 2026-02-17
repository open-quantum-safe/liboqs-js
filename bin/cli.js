#!/usr/bin/env node

/**
 * @fileoverview CLI entry point for @oqs/liboqs-js
 * @description Command-line interface for post-quantum cryptography operations
 */

import process from 'node:process';
import { createCLI } from '../src/cli/index.js';

const cli = createCLI();

cli.parse(process.argv.slice(2)).catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});
