#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { ConfigError, loadConfigFile } from './config';
import { hashSecret, randomToken } from './crypto';
import { rotateKeysFile } from './keys';
import { startServer } from './server';

const DEFAULT_CONFIG = 'oidc-rbac.config.json';
const DEFAULT_KEYS = 'keys.json';

const HELP = `oidc-rbac: an OpenID Connect provider with role-based access control

Usage:
  oidc-rbac init [--force]               Create ${DEFAULT_CONFIG} and ${DEFAULT_KEYS} in this folder
  oidc-rbac start [--config <file>]      Start the provider
  oidc-rbac check [--config <file>]      Validate a config file
  oidc-rbac hash [<secret>]              Hash a password or client secret (reads stdin if omitted)
  oidc-rbac keygen [--out <file>] [--keep <n>]
                                         Add a new signing key (rotation); keeps the newest n (default 2)

Options:
  -c, --config <file>   Config file (default: ${DEFAULT_CONFIG})
  -h, --help            Show this help
  -v, --version         Show the version`;

function version(): string {
  return JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
}

async function readSecret(): Promise<string> {
  if (!process.stdin.isTTY) {
    let data = '';
    for await (const chunk of process.stdin) data += chunk;
    return data.replace(/\r?\n$/, '');
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const answer = await rl.question('Secret to hash: ');
  rl.close();
  return answer;
}

async function init(force: boolean) {
  const configPath = resolve(DEFAULT_CONFIG);
  const keysPath = resolve(DEFAULT_KEYS);
  for (const path of [configPath, keysPath]) {
    if (existsSync(path) && !force) throw new ConfigError(`${path} already exists (use --force to overwrite).`);
  }

  const password = randomToken(12);
  const clientSecret = randomToken(24);
  const config = {
    issuer: 'http://localhost:4000',
    audience: 'my-api',
    name: 'oidc-rbac',
    keys: `./${DEFAULT_KEYS}`,
    store: { type: 'sqlite', path: './oidc-rbac.db' },
    users: [
      {
        sub: 'admin',
        username: 'admin',
        passwordHash: hashSecret(password),
        name: 'Administrator',
        email: 'admin@example.com',
        roles: ['admin'],
      },
    ],
    clients: [
      {
        clientId: 'my-app',
        name: 'My App',
        secretHash: hashSecret(clientSecret),
        redirectUris: ['http://localhost:3000/callback'],
      },
    ],
  };
  await writeFile(configPath, JSON.stringify(config, null, 2) + '\n');
  if (force && existsSync(keysPath)) await writeFile(keysPath, JSON.stringify({ keys: [] }));
  await rotateKeysFile(keysPath, 1);

  console.log(`Created ${DEFAULT_CONFIG} and ${DEFAULT_KEYS}.

  User      admin / ${password}
  Client    my-app / ${clientSecret}
            redirect URI http://localhost:3000/callback

These credentials are shown only once. Keep ${DEFAULT_KEYS} secret and out of version control.
Start the provider with: npx oidc-rbac start`);
}

async function main(argv: string[]) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      config: { type: 'string', short: 'c', default: DEFAULT_CONFIG },
      out: { type: 'string', default: DEFAULT_KEYS },
      keep: { type: 'string', default: '2' },
      force: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  const [command, arg] = positionals;

  if (values.version) return console.log(version());
  if (values.help || !command) return console.log(HELP);

  switch (command) {
    case 'init':
      return init(values.force);
    case 'start':
      await startServer(await loadConfigFile(values.config));
      return;
    case 'check': {
      const config = await loadConfigFile(values.config);
      console.log(`${values.config} is valid: ${config.users.length} user(s), ${config.clients.length} client(s).`);
      return;
    }
    case 'hash':
      return console.log(hashSecret(arg ?? (await readSecret())));
    case 'keygen': {
      const keep = Number(values.keep);
      if (!Number.isInteger(keep) || keep < 1) throw new ConfigError('--keep must be a positive integer.');
      const { added, removed } = await rotateKeysFile(resolve(values.out), keep);
      console.log(`Added signing key ${added} to ${values.out}; it signs new tokens after the next start.`);
      if (removed.length) console.log(`Removed old key(s): ${removed.join(', ')}`);
      return;
    }
    default:
      throw new ConfigError(`Unknown command "${command}".\n\n${HELP}`);
  }
}

main(process.argv.slice(2)).catch((err) => {
  console.error(err instanceof ConfigError ? err.message : err);
  process.exit(1);
});
