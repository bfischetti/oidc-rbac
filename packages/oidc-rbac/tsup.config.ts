import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/sqlite.ts', 'src/postgres.ts', 'src/cli.ts'],
  format: ['esm'],
  target: 'node22',
  dts: { entry: ['src/index.ts', 'src/sqlite.ts', 'src/postgres.ts'] },
  sourcemap: true,
  clean: true,
  external: ['pg'],
  // node:sqlite only exists with the node: prefix.
  removeNodeProtocol: false,
});
