export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export interface LoginPageContext {
  // Product name shown on the card (the `name` option).
  brand: string;
  clientName: string;
  error?: string;
  // Pre-rendered hidden inputs carrying the authorize request and CSRF token; put inside the form.
  hiddenFields: string;
  // Where the form must POST.
  action: string;
  // Previously entered username, to refill the field after a failed attempt.
  username?: string;
}

export type LoginPageRenderer = (ctx: LoginPageContext) => string;

const styles = `
  :root{--bg:#f5f6f8;--card:#fff;--text:#1a1d23;--muted:#5f6673;--border:#dfe2e7;--accent:#2457d6;--accent-text:#fff;--error:#b42318;--error-bg:#fef3f2}
  @media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--text:#e7e9ee;--muted:#9aa1ad;--border:#2a2f38;--accent:#5b8cff;--accent-text:#0b0d10;--error:#ff8a80;--error-bg:#2a1414}}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:16px}
  .card{width:100%;max-width:380px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:32px}
  .brand{font-weight:600;letter-spacing:.02em;color:var(--muted);font-size:13px;text-transform:uppercase;margin-bottom:20px}
  h1{font-size:22px;margin:0 0 4px}
  p{margin:0 0 24px;color:var(--muted)}
  label{display:block;font-size:13px;font-weight:500;margin-bottom:16px}
  input{display:block;width:100%;margin-top:6px;padding:10px 12px;font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px}
  input:focus{outline:2px solid var(--accent);outline-offset:-1px}
  button{width:100%;padding:11px;font:inherit;font-weight:600;color:var(--accent-text);background:var(--accent);border:0;border-radius:8px;cursor:pointer;margin-top:8px}
  .error{color:var(--error);background:var(--error-bg);padding:10px 12px;border-radius:8px;font-size:14px}
`;

function layout(brand: string, title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} · ${escapeHtml(brand)}</title><style>${styles}</style></head>
<body><main class="card"><div class="brand">${escapeHtml(brand)}</div>${body}</main></body>
</html>`;
}

export const defaultLoginPage: LoginPageRenderer = (ctx) =>
  layout(
    ctx.brand,
    'Sign in',
    `<h1>Sign in</h1>
    <p>to continue to <strong>${escapeHtml(ctx.clientName)}</strong></p>
    ${ctx.error ? `<p class="error" role="alert">${escapeHtml(ctx.error)}</p>` : ''}
    <form method="post" action="${escapeHtml(ctx.action)}">
      ${ctx.hiddenFields}
      <label>Username <input name="username" value="${escapeHtml(ctx.username ?? '')}" autocomplete="username" autofocus required></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Sign in</button>
    </form>`,
  );

export function errorPage(brand: string, message: string): string {
  return layout(brand, 'Error', `<h1>Something went wrong</h1><p class="error">${escapeHtml(message)}</p>`);
}
