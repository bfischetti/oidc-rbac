import { createClientApp } from './app';

const port = Number(process.env.PORT ?? 4002);

createClientApp({
  issuer: process.env.ISSUER ?? 'http://localhost:4000',
  clientId: process.env.CLIENT_ID ?? 'console',
  clientSecret: process.env.CLIENT_SECRET ?? 'console-secret',
  redirectUri: process.env.REDIRECT_URI ?? `http://localhost:${port}/callback`,
  apiUrl: process.env.API_URL ?? 'http://localhost:4001',
}).listen(port, () => {
  console.log(`[client] Console listening at http://localhost:${port}`);
});
