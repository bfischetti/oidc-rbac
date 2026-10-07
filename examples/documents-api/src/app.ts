import express from 'express';
import { oidcRbac, type OidcRbacOptions } from 'oidc-rbac-express';

interface Document {
  id: string;
  title: string;
  owner: string;
}

// This API's own Role-to-Permission table. The provider only knows Role names.
export const permissions = {
  admin: ['documents:read', 'documents:write', 'documents:delete'],
  editor: ['documents:read', 'documents:write'],
  viewer: ['documents:read'],
};

export function createDocumentsApi(options: Omit<OidcRbacOptions, 'permissions'>) {
  const { requirePermission } = oidcRbac({ ...options, permissions });
  const documents: Document[] = [
    { id: '1', title: 'Quarterly plan', owner: 'u-alice' },
    { id: '2', title: 'Release notes', owner: 'u-bob' },
  ];
  let nextId = 3;

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    res.on('finish', () => console.log(`[api] ${req.method} ${req.path} -> ${res.statusCode}`));
    next();
  });

  app.get('/documents', ...requirePermission('documents:read'), (_req, res) => {
    res.json(documents);
  });

  app.post('/documents', ...requirePermission('documents:write'), (req, res) => {
    const doc = { id: String(nextId++), title: String(req.body?.title ?? 'Untitled'), owner: req.auth!.sub };
    documents.push(doc);
    res.status(201).json(doc);
  });

  app.delete('/documents/:id', ...requirePermission('documents:delete'), (req, res) => {
    const index = documents.findIndex((d) => d.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'not_found' });
    documents.splice(index, 1);
    res.status(204).end();
  });

  return app;
}
