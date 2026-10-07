import type { NextFunction, Request, Response } from 'express';
import { timingSafeEqual } from 'node:crypto';

export function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return decodeURIComponent(rest.join('='));
  }
  return undefined;
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

// Applied to every provider response. The login page gets a strict CSP and can't be framed.
export function securityHeaders(_req: Request, res: Response, next: NextFunction) {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
  });
  next();
}

export interface RateLimitOptions {
  windowMs: number;
  max: number;
}

// Fixed-window, in-process limiter keyed by client IP. Behind a proxy, set `trustProxy`
// so req.ip is the real client. Run one instance per limiter, or put a shared limiter in front.
export function rateLimit(options: RateLimitOptions, now: () => number) {
  const hits = new Map<string, { count: number; resetAt: number }>();
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip ?? 'unknown';
    const t = now();
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= t) {
      entry = { count: 0, resetAt: t + options.windowMs };
      hits.set(key, entry);
      if (hits.size > 10_000) for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
    }
    entry.count++;
    if (entry.count > options.max) {
      res.set('Retry-After', String(Math.ceil((entry.resetAt - t) / 1000)));
      return res.status(429).json({ error: 'too_many_requests', error_description: 'Too many requests, slow down.' });
    }
    next();
  };
}
