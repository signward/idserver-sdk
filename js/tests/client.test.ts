import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { SignJWT, exportJWK, generateSecret } from 'jose';

import { IdServerClient, InvalidTokenError, TokenExchangeError, userFromClaims } from '../src/index.js';
import { requireAuth, requireRole } from '../src/express.js';

// ----------------------------------------------------------------------------
// Fake IdServer — a tiny HTTP server that serves discovery, JWKS, token, userinfo
// ----------------------------------------------------------------------------

interface FakeServerState {
  authority: string;
  secret: Uint8Array;
  jwk: Record<string, any>;
  tokenResponse: Record<string, unknown>;
  server: Server;
}

async function startFakeIdServer(): Promise<FakeServerState> {
  const secret = await generateSecret('HS256', { extractable: true });
  const jwk = await exportJWK(secret);
  jwk.kid = 'default';
  jwk.alg = 'HS256';
  jwk.use = 'sig';

  const state: Partial<FakeServerState> = { secret: secret as Uint8Array, jwk };

  const server = createServer((req, res) => {
    const url = new URL(req.url!, `http://${req.headers.host}`);
    const path = url.pathname;

    const json = (obj: unknown, status = 200) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    if (path === '/.well-known/openid-configuration') {
      const base = state.authority!;
      return json({
        issuer: base,
        authorization_endpoint: `${base}/connect/authorize`,
        token_endpoint: `${base}/connect/token`,
        userinfo_endpoint: `${base}/connect/userinfo`,
        end_session_endpoint: `${base}/connect/endsession`,
        jwks_uri: `${base}/.well-known/jwks`,
      });
    }
    if (path === '/.well-known/jwks') {
      return json({ keys: [state.jwk] });
    }
    if (path === '/connect/token' && req.method === 'POST') {
      return json(state.tokenResponse ?? { access_token: 'test', token_type: 'Bearer' });
    }
    if (path === '/connect/userinfo') {
      return json({
        sub: '11111111-1111-1111-1111-111111111111',
        email: 'a@b.c',
        roles: ['member'],
      });
    }
    json({ error: 'not_found' }, 404);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  state.authority = `http://127.0.0.1:${port}`;
  state.server = server;
  state.tokenResponse = {
    access_token: 'placeholder',
    token_type: 'Bearer',
    expires_in: 900,
  };

  return state as FakeServerState;
}

async function signTestJwt(
  secret: Uint8Array,
  issuer: string,
  claims: Record<string, unknown>,
  opts: { expiresIn?: string; expired?: boolean } = {},
): Promise<string> {
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256', kid: 'default' })
    .setIssuer(issuer)
    .setAudience('idserver-api')
    .setIssuedAt();

  if (opts.expired) {
    jwt.setExpirationTime(Math.floor(Date.now() / 1000) - 500);
  } else {
    jwt.setExpirationTime(opts.expiresIn ?? '10m');
  }

  return jwt.sign(secret);
}

// ----------------------------------------------------------------------------

describe('userFromClaims', () => {
  it('extracts basic fields', () => {
    const u = userFromClaims({
      sub: '11111111-1111-1111-1111-111111111111',
      email: 'alice@example.com',
      given_name: 'Alice',
      family_name: 'Smith',
      tenant_id: '22222222-2222-2222-2222-222222222222',
      roles: ['admin', 'member'],
      custom_roles: ['billing'],
    });
    assert.equal(u.userId, '11111111-1111-1111-1111-111111111111');
    assert.equal(u.email, 'alice@example.com');
    assert.equal(u.name, 'Alice Smith');
    assert.deepEqual(u.roles, ['admin', 'member']);
    assert.deepEqual(u.customRoles, ['billing']);
  });

  it('role helpers are case-insensitive', () => {
    const u = userFromClaims({ sub: 'x', roles: ['Admin'], custom_roles: ['Billing'] });
    assert.ok(u.hasRole('admin'));
    assert.ok(!u.hasRole('editor'));
    assert.ok(u.hasCustomRole('BILLING'));
    assert.ok(u.hasAnyRole('editor', 'admin'));
    assert.ok(u.hasAllRoles('admin', 'billing'));
    assert.ok(!u.hasAllRoles('admin', 'editor'));
  });

  it('handles single-string roles and missing claims', () => {
    const u1 = userFromClaims({ sub: 'x', roles: 'admin' });
    assert.deepEqual(u1.roles, ['admin']);

    const u2 = userFromClaims({ sub: 'x' });
    assert.deepEqual(u2.roles, []);
    assert.deepEqual(u2.customRoles, []);
  });
});

describe('IdServerClient', () => {
  let fake: FakeServerState;
  let client: IdServerClient;

  before(async () => {
    fake = await startFakeIdServer();
    client = new IdServerClient({
      authority: fake.authority,
      clientId: 'cid',
      clientSecret: 'sec',
    });
  });

  after(() => fake.server.close());

  it('builds authorize URL', () => {
    const url = client.authorizeUrl({ redirectUri: 'https://app/cb', state: 'xyz' });
    assert.ok(url.includes('response_type=code'));
    assert.ok(url.includes('state=xyz'));
    assert.ok(url.includes('client_id=cid'));
  });

  it('builds authorize URL with PKCE', async () => {
    const { url, verifier } = await client.authorizeUrlWithPkce({ redirectUri: 'https://app/cb' });
    assert.ok(verifier.length >= 43);
    assert.ok(url.includes('code_challenge='));
    assert.ok(url.includes('code_challenge_method=S256'));
  });

  it('fetches discovery + jwks (cached)', async () => {
    const d = await client.discovery();
    assert.ok(d.jwks_uri.includes('/.well-known/jwks'));
    const d2 = await client.discovery();
    assert.strictEqual(d, d2); // cache hit
  });

  it('exchanges code for tokens', async () => {
    // Prepare a valid token to be returned
    const token = await signTestJwt(fake.secret, fake.authority, {
      sub: '11111111-1111-1111-1111-111111111111',
      email: 'alice@example.com',
      roles: ['admin'],
    });
    fake.tokenResponse = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: 900,
    };

    const tokens = await client.exchangeCode('authcode', { redirectUri: 'https://app/cb' });
    assert.equal(tokens.access_token, token);
  });

  it('validates a JWT and returns a User', async () => {
    const token = await signTestJwt(fake.secret, fake.authority, {
      sub: '11111111-1111-1111-1111-111111111111',
      email: 'alice@example.com',
      roles: ['admin', 'member'],
      custom_roles: ['billing'],
    });
    const user = await client.validateToken(token);
    assert.equal(user.email, 'alice@example.com');
    assert.ok(user.hasRole('admin'));
    assert.ok(user.hasCustomRole('billing'));
  });

  it('rejects expired tokens', async () => {
    const token = await signTestJwt(
      fake.secret,
      fake.authority,
      { sub: '11111111-1111-1111-1111-111111111111' },
      { expired: true },
    );
    await assert.rejects(
      () => client.validateToken(token),
      (err) => err instanceof InvalidTokenError,
    );
  });

  it('rejects malformed tokens', async () => {
    await assert.rejects(
      () => client.validateToken('not.a.token'),
      (err) => err instanceof InvalidTokenError,
    );
  });

  it('fetches userinfo', async () => {
    const user = await client.userinfo('any-token');
    assert.equal(user.email, 'a@b.c');
  });

  it('builds end_session URL', async () => {
    const url = await client.endSessionUrl({ postLogoutRedirectUri: 'https://app/' });
    assert.ok(url.includes('post_logout_redirect_uri'));
    assert.ok(url.includes('/connect/endsession'));
  });
});

describe('Express middleware', () => {
  let fake: FakeServerState;
  let client: IdServerClient;

  before(async () => {
    fake = await startFakeIdServer();
    client = new IdServerClient({
      authority: fake.authority,
      clientId: 'cid',
    });
  });

  after(() => fake.server.close());

  // Helper: build a fake express req/res/next
  function mockReqRes(headers: Record<string, string> = {}) {
    const res: {
      statusCode?: number;
      headers: Record<string, string>;
      body?: unknown;
      status(code: number): typeof res;
      set(h: string, v: string): typeof res;
      json(obj: unknown): void;
    } = {
      headers: {},
      status(code) {
        this.statusCode = code;
        return this;
      },
      set(h, v) {
        this.headers[h] = v;
        return this;
      },
      json(obj) {
        this.body = obj;
      },
    };
    const req = { headers, user: undefined as unknown } as any;
    let nextCalled = false;
    const next = (() => {
      nextCalled = true;
    }) as any;
    return { req, res, next, nextCalled: () => nextCalled };
  }

  it('rejects missing Authorization header', async () => {
    const mw = requireAuth(client);
    const { req, res, next, nextCalled } = mockReqRes();
    await mw(req as any, res as any, next as any);
    assert.equal(res.statusCode, 401);
    assert.equal(nextCalled(), false);
  });

  it('rejects malformed header', async () => {
    const mw = requireAuth(client);
    const { req, res, next, nextCalled } = mockReqRes({ authorization: 'Basic xxx' });
    await mw(req as any, res as any, next as any);
    assert.equal(res.statusCode, 401);
    assert.equal(nextCalled(), false);
  });

  it('populates req.user for valid token', async () => {
    const token = await signTestJwt(fake.secret, fake.authority, {
      sub: '11111111-1111-1111-1111-111111111111',
      email: 'alice@example.com',
      roles: ['admin'],
    });
    const mw = requireAuth(client);
    const { req, res, next, nextCalled } = mockReqRes({ authorization: `Bearer ${token}` });
    await mw(req as any, res as any, next as any);
    assert.equal(nextCalled(), true);
    assert.equal(req.user.email, 'alice@example.com');
    assert.ok(req.user.hasRole('admin'));
  });

  it('requireRole grants admin', async () => {
    const roleMw = requireRole('admin');
    const { req, res, next, nextCalled } = mockReqRes();
    req.user = userFromClaims({ sub: 'x', roles: ['admin'] });
    roleMw(req as any, res as any, next as any);
    assert.equal(nextCalled(), true);
  });

  it('requireRole rejects without role', async () => {
    const roleMw = requireRole('admin');
    const { req, res, next, nextCalled } = mockReqRes();
    req.user = userFromClaims({ sub: 'x', roles: ['member'] });
    roleMw(req as any, res as any, next as any);
    assert.equal(res.statusCode, 403);
    assert.equal(nextCalled(), false);
  });

  it('requireRole with requireAll=true enforces AND', async () => {
    const roleMw = requireRole('admin', 'billing', { requireAll: true });
    const { req, res, next, nextCalled } = mockReqRes();
    req.user = userFromClaims({ sub: 'x', roles: ['admin'] });
    roleMw(req as any, res as any, next as any);
    assert.equal(res.statusCode, 403);
    assert.equal(nextCalled(), false);
  });

  it('requireRole considers custom roles by default', async () => {
    const roleMw = requireRole('billing');
    const { req, res, next, nextCalled } = mockReqRes();
    req.user = userFromClaims({ sub: 'x', custom_roles: ['billing'] });
    roleMw(req as any, res as any, next as any);
    assert.equal(nextCalled(), true);
  });
});
