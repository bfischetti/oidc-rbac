import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';

const url = z.url({ protocol: /^https?$/ });
const ttl = z.number().int().positive();
const rateLimitRule = z.object({ windowMs: z.number().int().positive(), max: z.number().int().positive() });

const userSchema = z.object({
  sub: z.string().min(1),
  username: z.string().min(1),
  passwordHash: z.string().startsWith('scrypt$', 'must be a hash from `oidc-rbac hash`'),
  name: z.string().optional(),
  email: z.email().optional(),
  roles: z.array(z.string().min(1)).default([]),
});

const clientSchema = z.object({
  clientId: z.string().min(1),
  name: z.string().min(1),
  secretHash: z.string().startsWith('scrypt$', 'must be a hash from `oidc-rbac hash`').optional(),
  redirectUris: z.array(url).min(1),
});

export const configSchema = z
  .object({
    $schema: z.string().optional(),
    issuer: url,
    port: z.number().int().min(0).max(65535).optional(),
    host: z.string().optional(),
    audience: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
    name: z.string().optional(),
    // Path to a private JWKS from `oidc-rbac keygen`. Without it, a throwaway key is generated on each start.
    keys: z.string().optional(),
    store: z
      .discriminatedUnion('type', [
        z.object({ type: z.literal('memory') }),
        z.object({ type: z.literal('sqlite'), path: z.string().min(1) }),
        z.object({ type: z.literal('postgres'), connectionString: z.string().min(1) }),
      ])
      .default({ type: 'memory' }),
    lifetimes: z
      .object({ accessToken: ttl, idToken: ttl, refreshToken: ttl, authorizationCode: ttl })
      .partial()
      .optional(),
    rateLimit: z
      .union([z.literal(false), z.object({ login: rateLimitRule, token: rateLimitRule }).partial()])
      .optional(),
    // Passed to Express's "trust proxy" setting when running behind a reverse proxy.
    trustProxy: z.union([z.boolean(), z.number(), z.string()]).optional(),
    users: z.array(userSchema).default([]),
    clients: z.array(clientSchema).default([]),
  })
  .superRefine((config, ctx) => {
    const dupes = (values: string[]) => values.filter((v, i) => values.indexOf(v) !== i);
    for (const sub of dupes(config.users.map((u) => u.sub))) {
      ctx.addIssue({ code: 'custom', path: ['users'], message: `duplicate sub "${sub}"` });
    }
    for (const name of dupes(config.users.map((u) => u.username))) {
      ctx.addIssue({ code: 'custom', path: ['users'], message: `duplicate username "${name}"` });
    }
    for (const id of dupes(config.clients.map((c) => c.clientId))) {
      ctx.addIssue({ code: 'custom', path: ['clients'], message: `duplicate clientId "${id}"` });
    }
  });

export type Config = z.infer<typeof configSchema>;

export class ConfigError extends Error {}

// Replaces ${VAR} in every string with the environment variable's value.
function interpolate(value: unknown, env: NodeJS.ProcessEnv, path: string): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{([A-Z0-9_]+)\}/gi, (_, name: string) => {
      const replacement = env[name];
      if (replacement === undefined) throw new ConfigError(`${path}: environment variable ${name} is not set`);
      return replacement;
    });
  }
  if (Array.isArray(value)) return value.map((v, i) => interpolate(v, env, `${path}[${i}]`));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, interpolate(v, env, path ? `${path}.${k}` : k)]));
  }
  return value;
}

export function parseConfig(raw: unknown, options: { baseDir?: string; env?: NodeJS.ProcessEnv } = {}): Config {
  const result = configSchema.safeParse(interpolate(raw, options.env ?? process.env, ''));
  if (!result.success) throw new ConfigError(`Invalid configuration:\n${z.prettifyError(result.error)}`);
  const config = result.data;
  // Relative file paths are relative to the config file, not the working directory.
  const baseDir = options.baseDir ?? process.cwd();
  if (config.keys) config.keys = resolve(baseDir, config.keys);
  if (config.store.type === 'sqlite' && config.store.path !== ':memory:') {
    config.store.path = resolve(baseDir, config.store.path);
  }
  return config;
}

export async function loadConfigFile(path: string, env = process.env): Promise<Config> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    throw new ConfigError(`Cannot read config file ${path}. Create one with \`oidc-rbac init\`.`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`${path} is not valid JSON: ${(err as Error).message}`);
  }
  return parseConfig(raw, { baseDir: dirname(resolve(path)), env });
}
