/**
 * @fileoverview CLI main module
 */

import { parseArgs } from './parser.js';
import { handleKemCommand } from './commands/kem.js';
import { handleSigCommand } from './commands/sig.js';
import { handleListCommand } from './commands/list.js';
import { handleInfoCommand } from './commands/info.js';
import process from "node:process";

export function createCLI() {
  return {
    async parse(argv) {
      const parsed = parseArgs(argv);

      switch (parsed.command) {
        case 'kem':
          return await handleKemCommand(parsed);
        case 'sig':
          return await handleSigCommand(parsed);
        case 'list':
          return handleListCommand(parsed);
        case 'info':
          return handleInfoCommand(parsed);
        case 'help':
          printHelp();
          break;
        default:
          printHelp();
          process.exit(1);
      }
    }
  };
}

function printHelp() {
  console.log(`
liboqs - Post-quantum cryptography CLI

Usage:
  liboqs <command> [options]

Commands:
  kem keygen <algorithm>                      Generate KEM keypair
  kem encapsulate <algorithm> <public-key>    Encapsulate to create shared secret
  kem decapsulate <algorithm> <ct> <sk>       Decapsulate to recover shared secret

  sig keygen <algorithm>                      Generate signature keypair
  sig sign <algorithm> <message> <sk>         Sign a message
  sig verify <algorithm> <msg> <sig> <pk>     Verify a signature

  list [--kem|--sig]                          List available algorithms
  info <algorithm>                            Show algorithm information

Options:
  --format <hex|base64|raw>                   Output encoding (default: hex)
  --input-format <hex|base64>                 Input encoding (default: auto)
  --output <file>                             Write output to file
  --output-dir <dir>                          Directory for keygen output
  --help, -h                                  Show this help

Input Methods:
  - File path:          ./path/to/file
  - Direct string:      "hello world"
  - Hex/Base64:         hex:a1b2c3... or base64:SGVsbG8=
  - Stdin:              - (dash for piped input)
  - Env var:            LIBOQS_SECRET_KEY or $LIBOQS_SECRET_KEY

Examples:
  # Generate ML-KEM-768 keypair
  liboqs kem keygen ml-kem-768 --output-dir ./keys

  # Sign a message
  liboqs sig sign ml-dsa-65 "Hello" ./secret.key --output sig.bin

  # Verify with piped message
  echo "Hello" | liboqs sig verify ml-dsa-65 - sig.bin ./public.key

  # Use environment variables
  export LIBOQS_SECRET_KEY="$(cat secret.key)"
  liboqs sig sign ml-dsa-65 message.txt LIBOQS_SECRET_KEY

For more information: https://open-quantum-safe.github.io/liboqs-js
`);
}
