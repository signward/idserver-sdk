/**
 * Express middleware for IdServer bearer-token authentication.
 *
 * Usage:
 *
 * ```ts
 * import express from 'express';
 * import { IdServerClient } from '@signward/idserver-client';
 * import { requireAuth, requireRole } from '@signward/idserver-client/express';
 *
 * const app = express();
 * const idserver = new IdServerClient({
 *   authority: 'https://mytenant.signward.com',
 *   clientId: 'my-api',
 *   clientSecret: '...',
 * });
 *
 * app.get('/me', requireAuth(idserver), (req, res) => {
 *   res.json({ email: req.user!.email, roles: req.user!.roles });
 * });
 *
 * app.get('/admin', requireAuth(idserver), requireRole('admin'), (req, res) => {
 *   res.json({ ok: true });
 * });
 * ```
 */

import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { IdServerClient } from './client.js';
import { InvalidTokenError } from './errors.js';
import type { User, ValidateTokenOptions } from './types.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

export interface RequireAuthOptions extends ValidateTokenOptions {
  /** Custom header name (default: `Authorization`). */
  header?: string;
  /** Custom error responder. Receives the Error and (res, next). */
  onError?: (err: Error, req: Request, res: Response, next: NextFunction) => void;
}

function defaultOnError(err: Error, _req: Request, res: Response, _next: NextFunction): void {
  const isInvalidToken = err instanceof InvalidTokenError;
  const status = isInvalidToken ? 401 : 500;
  res
    .status(status)
    .set('WWW-Authenticate', 'Bearer error="invalid_token"')
    .json({ error: err.name ?? 'Error', message: err.message });
}

/**
 * Create a middleware that validates the bearer token and populates `req.user`.
 */
export function requireAuth(
  client: IdServerClient,
  options: RequireAuthOptions = {},
): RequestHandler {
  const headerName = (options.header ?? 'authorization').toLowerCase();
  const onError = options.onError ?? defaultOnError;

  return async (req, res, next) => {
    const headerValue = req.headers[headerName];
    const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
    if (!raw) {
      return onError(new InvalidTokenError('Missing Authorization header'), req, res, next);
    }
    const match = /^Bearer\s+(.+)$/i.exec(raw);
    if (!match) {
      return onError(new InvalidTokenError('Authorization header must be Bearer'), req, res, next);
    }
    const token = match[1]!;
    try {
      const user = await client.validateToken(token, {
        audience: options.audience,
        leeway: options.leeway,
      });
      req.user = user;
      next();
    } catch (err) {
      onError(err as Error, req, res, next);
    }
  };
}

export interface RequireRoleOptions {
  /** Require ALL listed roles (default: false — ANY). */
  requireAll?: boolean;
  /** Also check per-tenant custom roles (default: true). */
  includeCustom?: boolean;
}

/**
 * Create a middleware that enforces role membership on `req.user`.
 * Must be used AFTER {@link requireAuth}.
 */
export function requireRole(
  ...rolesOrOptions: (string | RequireRoleOptions)[]
): RequestHandler {
  const roles: string[] = [];
  let opts: RequireRoleOptions = {};
  for (const item of rolesOrOptions) {
    if (typeof item === 'string') roles.push(item);
    else opts = item;
  }
  const includeCustom = opts.includeCustom ?? true;
  const requireAll = opts.requireAll ?? false;

  return (req, res, next) => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const check = (role: string): boolean =>
      user.hasRole(role) || (includeCustom && user.hasCustomRole(role));
    const ok = requireAll ? roles.every(check) : roles.some(check);
    if (!ok) {
      res.status(403).json({ error: 'Forbidden', message: 'Insufficient role' });
      return;
    }
    next();
  };
}
