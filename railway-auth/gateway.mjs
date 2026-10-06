import http from 'node:http';
import { createHash } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export function readConfig(env = process.env) {
  const resource = new URL(env.MCP_PUBLIC_URL);
  if (resource.protocol !== 'https:' || resource.pathname !== '/mcp' || resource.search || resource.hash || resource.username || resource.password) {
    throw new Error('MCP_PUBLIC_URL must be the exact public HTTPS /mcp URL');
  }
  const issuer = new URL(env.AUTH0_ISSUER);
  if (issuer.protocol !== 'https:' || issuer.pathname !== '/' || issuer.search || issuer.hash || issuer.username || issuer.password) {
    throw new Error('AUTH0_ISSUER must be an HTTPS issuer ending in /');
  }
  const audience = env.AUTH0_AUDIENCE || resource.href;
  if (audience !== resource.href) throw new Error('AUTH0_AUDIENCE must equal MCP_PUBLIC_URL');
  const allowedEmails = new Set((env.MCP_ALLOWED_EMAILS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean));
  const allowedSubjects = new Set((env.MCP_ALLOWED_SUBJECTS || '').split(',').map(x => x.trim()).filter(Boolean));
  if (!allowedEmails.size && !allowedSubjects.size) throw new Error('An explicit account allowlist is required');
  const port = Number(env.PORT || 3000);
  const upstreamPort = Number(env.MCP_INTERNAL_PORT || 3001);
  if (![port, upstreamPort].every(x => Number.isInteger(x) && x > 0 && x <= 65535) || port === upstreamPort) {
    throw new Error('Public and internal ports must be valid and different');
  }
  return { resource: resource.href, issuer: issuer.href, audience, allowedEmails, allowedSubjects, port, upstreamPort };
}

export function createVerifier(config, { keys, fetchProfile = fetch } = {}) {
  const jwks = keys || createRemoteJWKSet(new URL('.well-known/jwks.json', config.issuer), { timeoutDuration: 5000 });
  const profiles = new Map();
  return async token => {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: config.issuer, audience: config.audience, algorithms: ['RS256'],
      requiredClaims: ['sub', 'exp', 'iat'], clockTolerance: 5,
    });
    if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.endsWith('@clients')) throw new Error('A user login is required');
    if (config.allowedSubjects.has(payload.sub)) return payload;
    if (!config.allowedEmails.size) throw new Error('Account not allowed');
    if (!(payload.scope || '').split(' ').includes('openid')) throw new Error('openid scope required');
    const cacheKey = createHash('sha256').update(token).digest('hex');
    const cached = profiles.get(cacheKey);
    let profile;
    if (cached && cached.until > Date.now()) profile = cached.profile;
    else {
      const response = await fetchProfile(new URL('userinfo', config.issuer), {
        headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('Unable to verify the login account');
      profile = await response.json();
      if (profiles.size >= 500) profiles.delete(profiles.keys().next().value);
      profiles.set(cacheKey, { profile, until: Math.min(Date.now() + 60000, payload.exp * 1000) });
    }
    if (profile.sub !== payload.sub || profile.email_verified !== true || typeof profile.email !== 'string' ||
      !config.allowedEmails.has(profile.email.toLowerCase())) throw new Error('Account not allowed');
    return payload;
  };
}

const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
function forwardHeaders(headers) {
  const blocked = new Set([...hopHeaders, ...(headers.connection || '').split(',').map(x => x.trim().toLowerCase()),
    'authorization', 'cookie', 'host', 'forwarded', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for']);
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !blocked.has(name.toLowerCase())));
}
function json(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(data));
}

export function createGateway(config, { verifyToken = createVerifier(config), ready = () => true } = {}) {
  const metadataUrl = new URL('/.well-known/oauth-protected-resource/mcp', config.resource).href;
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://gateway.invalid');
      if (req.method === 'GET' && ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'].includes(url.pathname)) {
        return json(res, 200, {
          resource: config.resource, authorization_servers: [config.issuer.replace(/\/$/, '')],
          scopes_supported: ['openid', 'profile', 'email'], bearer_methods_supported: ['header'],
          resource_name: 'Private Lark MCP',
        });
      }
      if (req.method === 'GET' && url.pathname === '/healthz') return json(res, ready() ? 200 : 503, { ready: ready() });
      if (url.pathname !== '/mcp') return json(res, 404, { error: 'not_found' });
      // Query parameters can override Lark credentials and token mode in the upstream CLI.
      if (url.search) return json(res, 400, { error: 'query_parameters_not_supported' });
      const auth = req.headers.authorization;
      const match = typeof auth === 'string' && /^Bearer ([A-Za-z0-9._~-]+)$/i.exec(auth);
      try {
        if (!match) throw new Error('Missing token');
        await verifyToken(match[1]);
      } catch {
        return json(res, 401, { error: 'authentication_required' }, {
          'WWW-Authenticate': `Bearer resource_metadata="${metadataUrl}", scope="openid profile email"${match ? ', error="invalid_token"' : ''}`,
        });
      }
      if (!ready()) return json(res, 503, { error: 'upstream_starting' });
      if (!['POST', 'GET', 'DELETE'].includes(req.method)) return json(res, 405, { error: 'method_not_allowed' }, { Allow: 'POST, GET, DELETE' });
      const chunks = [];
      let length = 0;
      for await (const chunk of req) {
        length += chunk.length;
        if (length > 1024 * 1024) return json(res, 413, { error: 'request_too_large' });
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks);
      const listTools = req.method === 'POST' && (() => {
        try { return JSON.parse(body.toString()).method === 'tools/list'; } catch { return false; }
      })();
      const headers = forwardHeaders(req.headers);
      headers['content-length'] = String(body.length);
      // Never send the Auth0 token to Lark; the upstream runs in tenant_access_token mode.
      const upstream = http.request({ hostname: '127.0.0.1', port: config.upstreamPort, path: '/mcp', method: req.method, headers }, response => {
        if (listTools && response.statusCode === 200) {
          const parts = [];
          let size = 0;
          response.on('data', chunk => {
            size += chunk.length;
            if (size > 8 * 1024 * 1024) response.destroy(new Error('Tools response too large'));
            else parts.push(chunk);
          });
          response.on('end', () => {
            try {
              const text = Buffer.concat(parts).toString();
              const data = response.headers['content-type']?.includes('text/event-stream')
                ? text.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n')
                : text;
              const rpc = JSON.parse(data);
              if (rpc.result?.tools) rpc.result.tools = rpc.result.tools.map(tool => ({
                ...tool, securitySchemes: [{ type: 'oauth2', scopes: ['openid', 'profile', 'email'] }],
              }));
              json(res, 200, rpc);
            } catch { if (!res.headersSent) json(res, 502, { error: 'invalid_upstream_tools_response' }); }
          });
          response.on('error', () => { if (!res.headersSent) json(res, 502, { error: 'upstream_unavailable' }); });
          return;
        }
        const responseHeaders = Object.fromEntries(Object.entries(response.headers).filter(([name]) => !hopHeaders.has(name)));
        res.writeHead(response.statusCode, { ...responseHeaders, 'Cache-Control': 'no-store' });
        response.pipe(res);
        response.on('error', () => res.destroy());
      });
      upstream.setTimeout(120000, () => upstream.destroy());
      upstream.on('error', () => {
        if (!res.headersSent) json(res, 502, { error: 'upstream_unavailable' });
        else res.destroy();
      });
      res.on('close', () => upstream.destroy());
      upstream.end(body);
    } catch {
      if (!res.headersSent) json(res, 400, { error: 'invalid_request' });
      else res.destroy();
    }
  });
}
