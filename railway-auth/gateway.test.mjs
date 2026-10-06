import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPair, SignJWT, exportJWK, createLocalJWKSet } from 'jose';
import { readConfig, createVerifier, createGateway } from './gateway.mjs';

const env = {
  MCP_PUBLIC_URL: 'https://mcp.example.com/mcp', AUTH0_ISSUER: 'https://login.example.com/',
  MCP_ALLOWED_EMAILS: 'owner@example.com', PORT: '3000', MCP_INTERNAL_PORT: '3001',
};
const config = readConfig(env);
const { publicKey, privateKey } = await generateKeyPair('RS256');
const publicJwk = { ...await exportJWK(publicKey), kid: 'test-key' };
const keys = createLocalJWKSet({ keys: [publicJwk] });
const profile = (overrides = {}) => new Response(JSON.stringify({ sub: 'auth0|owner', email: 'owner@example.com', email_verified: true, ...overrides }), {
  status: 200, headers: { 'Content-Type': 'application/json' },
});
async function token(overrides = {}, signingKey = privateKey) {
  return new SignJWT({ scope: 'openid profile email', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setSubject(overrides.sub ?? 'auth0|owner')
    .setIssuer(overrides.iss ?? config.issuer).setAudience(overrides.aud ?? config.audience)
    .setIssuedAt().setExpirationTime(overrides.exp ?? '5m').sign(signingKey);
}
function verifier(overrides = {}) { return createVerifier(config, { keys, fetchProfile: async () => profile(), ...overrides }); }

test('configuration requires a public HTTPS /mcp resource, matching audience and account allowlist', () => {
  for (const override of [
    { MCP_ALLOWED_EMAILS: '' }, { AUTH0_AUDIENCE: 'https://wrong.example.com/' },
    { MCP_PUBLIC_URL: 'http://mcp.example.com/mcp' }, { MCP_PUBLIC_URL: 'https://mcp.example.com/mcp?token=x' },
    { AUTH0_ISSUER: 'https://login.example.com/other' }, { MCP_INTERNAL_PORT: '3000' },
  ]) assert.throws(() => readConfig({ ...env, ...override }));
});

test('verified allowlisted account succeeds and UserInfo cache does not expose raw tokens', async () => {
  let calls = 0;
  const verify = verifier({ fetchProfile: async (url, options) => {
    calls++;
    assert.equal(url.href, 'https://login.example.com/userinfo');
    assert.equal(options.redirect, 'error');
    return profile();
  } });
  const signed = await token();
  assert.equal((await verify(signed)).sub, 'auth0|owner');
  await verify(signed);
  assert.equal(calls, 1);
});

test('wrong issuer, audience, expired token, bad signature and non-JWT fail before UserInfo', async () => {
  const { privateKey: otherKey } = await generateKeyPair('RS256');
  const verify = verifier({ fetchProfile: async () => { throw new Error('UserInfo must not be called'); } });
  for (const signed of [
    await token({ iss: 'https://evil.example.com/' }), await token({ aud: 'another-api' }),
    await token({ exp: Math.floor(Date.now() / 1000) - 60 }), await token({}, otherKey), 'not-a-jwt',
  ]) await assert.rejects(() => verify(signed));
});

test('unverified email, unapproved email and UserInfo/JWT subject mismatch are rejected', async () => {
  for (const override of [{ email_verified: false }, { email: 'stranger@example.com' }, { sub: 'auth0|someone-else' }]) {
    await assert.rejects(() => verifier({ fetchProfile: async () => profile(override) })(tokenString));
  }
});
const tokenString = await token();

test('claims in a caller token cannot replace authenticated UserInfo email', async () => {
  await assert.rejects(() => verifier({ fetchProfile: async () => profile({ email: 'stranger@example.com' }) })(
    tokenStringWithForgedEmail,
  ));
});
const tokenStringWithForgedEmail = await token({ email: 'owner@example.com', email_verified: true });

test('machine-to-machine clients and missing openid scope do not get application access', async () => {
  for (const signed of [await token({ sub: 'service@clients' }), await token({ scope: 'email' })]) {
    await assert.rejects(() => verifier()(signed));
  }
});

test('UserInfo failure is closed, never anonymous fallback', async () => {
  await assert.rejects(() => verifier({ fetchProfile: async () => new Response('denied', { status: 401 }) })(tokenString));
});

test('explicit user subject allowlist works without a UserInfo request', async () => {
  const subjectConfig = readConfig({ ...env, MCP_ALLOWED_EMAILS: '', MCP_ALLOWED_SUBJECTS: 'auth0|owner' });
  const verify = createVerifier(subjectConfig, { keys, fetchProfile: async () => { throw new Error('unexpected UserInfo'); } });
  assert.equal((await verify(tokenString)).sub, 'auth0|owner');
  const strangerToken = await token({ sub: 'auth0|stranger' });
  await assert.rejects(() => verify(strangerToken));
});

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}
async function close(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

test('gateway blocks anonymous and invalid calls, advertises OAuth, and forwards only approved requests', async t => {
  let upstreamCalls = 0;
  let upstreamHeaders;
  const upstream = http.createServer((req, res) => {
    upstreamCalls++;
    upstreamHeaders = req.headers;
    assert.equal(req.url, '/mcp');
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"task_get","inputSchema":{"type":"object"}}]}}\n\n');
  });
  const upstreamPort = await listen(upstream);
  const gateway = createGateway({ ...config, upstreamPort }, { verifyToken: verifier() });
  const base = `http://127.0.0.1:${await listen(gateway)}`;
  t.after(async () => { await close(gateway); await close(upstream); });
  for (const auth of [undefined, 'Basic password', 'Bearer not-a-jwt']) {
    const result = await fetch(`${base}/mcp`, { method: 'POST', headers: auth ? { Authorization: auth } : {}, body: '{}' });
    assert.equal(result.status, 401);
    assert.match(result.headers.get('www-authenticate'), /resource_metadata="https:\/\/mcp.example.com\/\.well-known\/oauth-protected-resource\/mcp"/);
    await result.text();
  }
  assert.equal(upstreamCalls, 0);
  const discovery = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
  assert.equal(discovery.status, 200);
  assert.equal((await discovery.json()).resource, config.resource);
  const queryOverride = await fetch(`${base}/mcp?appId=other&tokenMode=user_access_token`, { headers: { Authorization: `Bearer ${tokenString}` } });
  assert.equal(queryOverride.status, 400);
  await queryOverride.text();
  assert.equal(upstreamCalls, 0);
  const result = await fetch(`${base}/mcp`, {
    method: 'POST', headers: { Authorization: `Bearer ${tokenString}`, Cookie: 'secret=example', 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  });
  assert.equal(result.status, 200);
  const listed = await result.json();
  assert.equal(listed.result.tools[0].name, 'task_get');
  assert.equal(listed.result.tools[0].securitySchemes[0].type, 'oauth2');
  assert.equal(upstreamCalls, 1);
  assert.equal(upstreamHeaders.authorization, undefined);
  assert.equal(upstreamHeaders.cookie, undefined);
  assert.equal(upstreamHeaders['content-type'], 'application/json');
});

test('readiness blocks authorized traffic until the private backend starts', async t => {
  const gateway = createGateway(config, { ready: () => false, verifyToken: async () => ({ sub: 'owner' }) });
  const base = `http://127.0.0.1:${await listen(gateway)}`;
  t.after(() => close(gateway));
  assert.equal((await fetch(`${base}/healthz`)).status, 503);
  assert.equal((await fetch(`${base}/mcp`, { headers: { Authorization: 'Bearer valid' } })).status, 503);
});
