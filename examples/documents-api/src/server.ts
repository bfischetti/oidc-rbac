import { createDocumentsApi } from './app';

const port = Number(process.env.PORT ?? 4001);

createDocumentsApi({
  issuer: process.env.ISSUER ?? 'http://localhost:4000',
  audience: process.env.API_AUDIENCE ?? 'documents-api',
}).listen(port, () => {
  console.log(`[api] Documents API listening at http://localhost:${port}`);
});
