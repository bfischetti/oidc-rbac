import type { Server } from 'node:http';
import express from 'express';
import type { Config } from './config';
import { staticClients, staticUsers } from './directory';
import { generateKeySet, loadKeySet } from './keys';
import { createProvider } from './provider';
import { MemoryStore } from './store/memory';
import type { Store } from './store/types';
import { consoleLogger, type Logger } from './types';

async function createStore(config: Config, logger: Logger): Promise<Store> {
  switch (config.store.type) {
    case 'memory':
      logger.warn('using the in-memory store: sign-ins and refresh tokens are lost on restart');
      return new MemoryStore();
    case 'sqlite': {
      const { SqliteStore } = await import('./store/sqlite');
      return new SqliteStore(config.store.path);
    }
    case 'postgres': {
      let Pool: typeof import('pg').Pool;
      try {
        ({ Pool } = (await import('pg')).default);
      } catch {
        throw new Error('The postgres store needs the "pg" package: npm install pg');
      }
      const { PostgresStore } = await import('./store/postgres');
      const store = new PostgresStore(new Pool({ connectionString: config.store.connectionString }));
      await store.migrate();
      return store;
    }
  }
}

// Runs a standalone provider from a validated config, as `oidc-rbac start` does.
export async function startServer(config: Config, logger: Logger = consoleLogger()): Promise<Server> {
  let keys;
  if (config.keys) {
    keys = await loadKeySet(config.keys);
  } else {
    logger.warn('no "keys" file configured: using a throwaway signing key (run `oidc-rbac keygen`)');
    keys = await generateKeySet();
  }

  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy !== undefined) app.set('trust proxy', config.trustProxy);

  const issuerUrl = new URL(config.issuer);
  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.use(
    issuerUrl.pathname.replace(/\/$/, '') || '/',
    createProvider({
      issuer: config.issuer,
      audience: config.audience,
      keys,
      users: staticUsers(config.users),
      clients: staticClients(config.clients),
      store: await createStore(config, logger),
      lifetimes: config.lifetimes,
      rateLimit: config.rateLimit,
      name: config.name,
      logger,
    }),
  );

  const port = config.port ?? Number(process.env.PORT ?? (issuerUrl.port || 4000));
  const host = config.host ?? process.env.HOST;
  return new Promise((resolve) => {
    const onListening = () => {
      logger.info(`issuer ${config.issuer} listening on ${host ?? '*'}:${port}`);
      logger.info(`${config.users.length} user(s), ${config.clients.length} client(s), ${keys.all.length} signing key(s)`);
      resolve(server);
    };
    const server = host ? app.listen(port, host, onListening) : app.listen(port, onListening);
  });
}
