import { createHash, randomBytes, randomUUID } from 'node:crypto';
import express, { type Request, type Response } from 'express';
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTVerifyGetKey } from 'jose';

export interface ClientConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  apiUrl: string;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface Session {
  pending?: { state: string; nonce: string; codeVerifier: string };
  tokens?: { idToken: string; accessToken: string; refreshToken?: string };
  lastResult?: string;
  log: string[];
}

const random = () => randomBytes(32).toString('base64url');

export function createClientApp(config: ClientConfig) {
  const sessions = new Map<string, Session>();
  let discovery: Discovery | undefined;
  let jwks: JWTVerifyGetKey | undefined;

  // Read the OP's endpoints from discovery instead of hard-coding them.
  async function discover() {
    if (!discovery) {
      const res = await fetch(`${config.issuer}/.well-known/openid-configuration`);
      discovery = (await res.json()) as Discovery;
      jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
    }
    return { discovery, jwks: jwks! };
  }

  function session(req: Request, res: Response): Session {
    const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
    if (sid && sessions.has(sid)) return sessions.get(sid)!;
    const id = randomUUID();
    const fresh: Session = { log: [] };
    sessions.set(id, fresh);
    res.cookie('sid', id, { httpOnly: true, sameSite: 'lax' });
    return fresh;
  }

  function log(s: Session, line: string) {
    console.log(`[client] ${line}`);
    s.log.push(line);
  }

  function basicAuth() {
    const creds = `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`;
    return `Basic ${Buffer.from(creds).toString('base64')}`;
  }

  async function callTokenEndpoint(s: Session, params: Record<string, string>) {
    const { discovery } = await discover();
    log(s, `POST ${discovery.token_endpoint} grant_type=${params.grant_type}`);
    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { Authorization: basicAuth(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params),
    });
    const body = await res.json();
    log(s, `  <- ${res.status}${body.error ? ` ${body.error}: ${body.error_description}` : ''}`);
    return { ok: res.ok, body };
  }

  const app = express();
  app.use(express.urlencoded({ extended: false }));

  app.get('/', (req, res) => {
    res.type('html').send(renderHome(session(req, res)));
  });

  // Step 1: send the browser to the OP with a fresh state, nonce and PKCE challenge.
  app.get('/login', async (req, res) => {
    const s = session(req, res);
    const { discovery } = await discover();
    const pending = { state: random(), nonce: random(), codeVerifier: random() };
    s.pending = pending;

    const url = new URL(discovery.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: 'openid profile email offline_access',
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: createHash('sha256').update(pending.codeVerifier).digest('base64url'),
      code_challenge_method: 'S256',
    }).toString();
    log(s, `redirect browser -> ${url.origin}${url.pathname} (state, nonce, code_challenge)`);
    res.redirect(url.toString());
  });

  // Step 2: the OP sends the browser back with a code; exchange it for tokens.
  app.get('/callback', async (req, res) => {
    const s = session(req, res);
    const pending = s.pending;
    s.pending = undefined;
    log(s, `browser returned to /callback`);

    if (req.query.error) {
      s.lastResult = `Sign-in failed: ${req.query.error} ${req.query.error_description ?? ''}`;
      return res.redirect('/');
    }
    if (!pending || req.query.state !== pending.state) {
      s.lastResult = 'Sign-in failed: state mismatch (possible CSRF).';
      return res.redirect('/');
    }
    if (req.query.iss !== config.issuer) {
      s.lastResult = 'Sign-in failed: response came from an unexpected issuer.';
      return res.redirect('/');
    }

    const { ok, body } = await callTokenEndpoint(s, {
      grant_type: 'authorization_code',
      code: String(req.query.code),
      redirect_uri: config.redirectUri,
      code_verifier: pending.codeVerifier,
    });
    if (!ok) {
      s.lastResult = `Token exchange failed: ${body.error}`;
      return res.redirect('/');
    }

    // The ID Token is for us: check signature, issuer, audience and the nonce we sent.
    const { jwks } = await discover();
    const { payload } = await jwtVerify(body.id_token, jwks, {
      issuer: config.issuer,
      audience: config.clientId,
    });
    if (payload.nonce !== pending.nonce) {
      s.lastResult = 'Sign-in failed: nonce mismatch (possible replay).';
      return res.redirect('/');
    }
    log(s, `ID Token verified for sub=${payload.sub}`);

    s.tokens = {
      idToken: body.id_token,
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
    };
    s.lastResult = `Signed in as ${payload.name ?? payload.sub}.`;
    res.redirect('/');
  });

  app.post('/refresh', async (req, res) => {
    const s = session(req, res);
    if (!s.tokens?.refreshToken) return res.redirect('/');
    const { ok, body } = await callTokenEndpoint(s, {
      grant_type: 'refresh_token',
      refresh_token: s.tokens.refreshToken,
    });
    if (ok) {
      s.tokens = { ...s.tokens, accessToken: body.access_token, refreshToken: body.refresh_token };
      s.lastResult = 'Tokens refreshed. The old Refresh Token is now spent.';
    } else {
      s.lastResult = `Refresh failed: ${body.error_description}`;
    }
    res.redirect('/');
  });

  // Calls the Resource Server with the Access Token as a Bearer credential.
  app.post('/call', async (req, res) => {
    const s = session(req, res);
    if (!s.tokens) return res.redirect('/');
    const action = String(req.body.action);
    const requests: Record<string, { method: string; path: string; body?: unknown }> = {
      read: { method: 'GET', path: '/documents' },
      write: { method: 'POST', path: '/documents', body: { title: `Note ${new Date().toISOString()}` } },
      delete: { method: 'DELETE', path: `/documents/${encodeURIComponent(String(req.body.id ?? '1'))}` },
    };
    const call = requests[action];
    if (!call) return res.redirect('/');

    log(s, `${call.method} ${config.apiUrl}${call.path} (Bearer access token)`);
    const apiRes = await fetch(`${config.apiUrl}${call.path}`, {
      method: call.method,
      headers: {
        Authorization: `Bearer ${s.tokens.accessToken}`,
        ...(call.body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: call.body ? JSON.stringify(call.body) : undefined,
    });
    const text = await apiRes.text();
    log(s, `  <- ${apiRes.status}`);
    s.lastResult = `${call.method} ${call.path} -> ${apiRes.status}\n${prettyJson(text)}`;
    res.redirect('/');
  });

  // Local sign-out only: the OP keeps no login session, so the next sign-in asks for a password again.
  app.post('/logout', (req, res) => {
    const s = session(req, res);
    s.tokens = undefined;
    s.lastResult = 'Signed out locally.';
    res.redirect('/');
  });

  return app;
}

function prettyJson(text: string): string {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function escape(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function decoded(token: string): string {
  return escape(JSON.stringify(decodeJwt(token), null, 2));
}

function renderHome(s: Session): string {
  const t = s.tokens;
  const claims = t ? decodeJwt(t.accessToken) : undefined;
  const content = t
    ? `
    <section class="panel session">
      <div>
        <div class="label">Signed in as</div>
        <div class="who">${escape(String(decodeJwt(t.idToken).name ?? claims?.sub))}</div>
        <div class="roles">${((claims?.roles as string[]) ?? []).map((r) => `<span class="chip">${escape(r)}</span>`).join('')}</div>
      </div>
      <div class="row">
        <form method="post" action="/refresh"><button class="secondary" ${t.refreshToken ? '' : 'disabled'}>Refresh tokens</button></form>
        <form method="post" action="/logout"><button class="secondary">Sign out</button></form>
      </div>
    </section>
    <section class="panel">
      <h2>Call the Documents API</h2>
      <div class="row">
        <form method="post" action="/call"><input type="hidden" name="action" value="read"><button><code>GET</code> /documents</button></form>
        <form method="post" action="/call"><input type="hidden" name="action" value="write"><button><code>POST</code> /documents</button></form>
        <form method="post" action="/call" class="inline"><input type="hidden" name="action" value="delete"><button><code>DELETE</code> /documents/</button><input name="id" value="1" aria-label="Document id"></form>
      </div>
      ${s.lastResult ? `<pre class="result">${escape(s.lastResult)}</pre>` : ''}
    </section>
    <div class="grid">
      <section class="panel"><h2>ID Token <span class="hint">audience: this app</span></h2><pre>${decoded(t.idToken)}</pre></section>
      <section class="panel"><h2>Access Token <span class="hint">audience: the API</span></h2><pre>${decoded(t.accessToken)}</pre></section>
    </div>
    <section class="panel"><h2>Refresh Token <span class="hint">opaque, single use</span></h2><pre>${escape(t.refreshToken ?? '(not issued)')}</pre></section>`
    : `
    <section class="panel empty">
      <h2>Not signed in</h2>
      <p>Sign in through the OpenID Provider to inspect your tokens and call the Documents API.</p>
      <a class="button" href="/login">Sign in</a>
      ${s.lastResult ? `<pre class="result">${escape(s.lastResult)}</pre>` : ''}
    </section>`;

  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Console · oidc-rbac</title>
<style>
  :root{--bg:#f5f6f8;--card:#fff;--text:#1a1d23;--muted:#5f6673;--border:#dfe2e7;--code:#f0f2f5;--accent:#2457d6;--accent-text:#fff;--chip:#e8eefc}
  @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--text:#e7e9ee;--muted:#9aa1ad;--border:#2a2f38;--code:#11141a;--accent:#5b8cff;--accent-text:#0b0d10;--chip:#1e2a45}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
  header{border-bottom:1px solid var(--border);background:var(--card)}
  header div,main{max-width:1080px;margin:0 auto;padding:14px 16px}
  header strong{font-size:15px}header span{color:var(--muted);margin-left:8px;font-size:14px}
  main{display:flex;flex-direction:column;gap:16px;padding-top:24px;padding-bottom:48px}
  .panel{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;min-width:0}
  h2{font-size:15px;margin:0 0 12px}.hint{font-weight:400;color:var(--muted);font-size:13px;margin-left:6px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
  .session{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
  .label{color:var(--muted);font-size:13px}.who{font-size:18px;font-weight:600}
  .roles{margin-top:6px;display:flex;gap:6px}.chip{background:var(--chip);color:var(--accent);border-radius:999px;padding:2px 10px;font-size:13px;font-weight:500}
  .row{display:flex;flex-wrap:wrap;gap:8px}form{margin:0}.inline{display:flex}
  .inline button{border-top-right-radius:0;border-bottom-right-radius:0}
  .inline input{width:56px;font:inherit;padding:8px;border:1px solid var(--border);border-left:0;border-radius:0 8px 8px 0;background:var(--bg);color:var(--text)}
  button,.button{display:inline-block;font:inherit;font-weight:500;padding:8px 14px;border-radius:8px;border:0;background:var(--accent);color:var(--accent-text);cursor:pointer;text-decoration:none}
  button.secondary{background:transparent;color:var(--text);border:1px solid var(--border)}
  button:disabled{opacity:.5;cursor:default}
  button code{font-weight:700;margin-right:4px}
  pre{margin:0;background:var(--code);border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-size:12.5px;line-height:1.45}
  .result{margin-top:14px}
  .empty p{color:var(--muted);margin:0 0 16px}
</style></head>
<body>
  <header><div><strong>oidc-rbac</strong><span>Console</span></div></header>
  <main>
    ${content}
    <section class="panel"><h2>Flow log <span class="hint">every HTTP hop this app made</span></h2><pre>${escape(s.log.join('\n') || 'No requests yet.')}</pre></section>
  </main>
</body>
</html>`;
}
