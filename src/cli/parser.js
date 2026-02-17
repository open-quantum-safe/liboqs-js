/**
 * @fileoverview CLI argument parser
 */

export function parseArgs(argv) {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    return { command: 'help' };
  }

  const command = argv[0];

  // Commands without subcommands: list, info
  const noSubcommandCommands = ['list', 'info'];
  const hasSubcommand = !noSubcommandCommands.includes(command) && argv[1] && !argv[1].startsWith('--');

  const subcommand = hasSubcommand ? argv[1] : null;
  const startIndex = hasSubcommand ? 2 : 1;

  const args = [];
  const options = {
    format: 'hex',
    inputFormat: 'auto',
    output: null,
    outputDir: null,
    kem: false,
    sig: false
  };

  // Parse arguments and flags
  for (let i = startIndex; i < argv.length; i++) {
    const arg = argv[i];

    if (arg.startsWith('--')) {
      const flag = arg.slice(2);

      if (flag === 'format' || flag === 'input-format' || flag === 'output' || flag === 'output-dir') {
        const value = argv[++i];
        if (!value) {
          throw new Error(`Missing value for --${flag}`);
        }

        if (flag === 'format') options.format = value;
        else if (flag === 'input-format') options.inputFormat = value;
        else if (flag === 'output') options.output = value;
        else if (flag === 'output-dir') options.outputDir = value;
      } else if (flag === 'kem') {
        options.kem = true;
      } else if (flag === 'sig') {
        options.sig = true;
      } else {
        throw new Error(`Unknown option: --${flag}`);
      }
    } else {
      args.push(arg);
    }
  }

  return {
    command,
    subcommand,
    args,
    options
  };
}
