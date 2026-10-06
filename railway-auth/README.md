# Private Railway deployment

The public `/mcp` endpoint requires an Auth0 user access token. The existing Lark CLI runs on `127.0.0.1:3001` and continues using the application identity. Auth0 credentials are never forwarded to Lark.

## Configuration

Keep the existing `APP_ID`, `APP_SECRET`, `LARK_DOMAIN`, `LARK_TOOLS`, and `PORT` values. Add:

- `AUTH0_ISSUER`: Auth0 tenant HTTPS URL including the final `/`.
- `MCP_PUBLIC_URL`: Exact public URL ending in `/mcp`.
- `AUTH0_AUDIENCE`: Same value as `MCP_PUBLIC_URL`; register this identifier as an Auth0 API using RS256.
- `MCP_ALLOWED_EMAILS`: Explicit comma-separated allowlist. Login emails must be verified by Auth0, and the returned UserInfo subject must match the verified JWT subject.

Alternatively use `MCP_ALLOWED_SUBJECTS` for an explicit list of Auth0 user IDs. Do not use machine-to-machine application IDs. An empty allowlist prevents startup. Missing or invalid authentication is always rejected; there is no anonymous fallback.

Remove Railway's previous Lark start-command override, so the Docker CMD starts the gateway, or set the start command to:

```
/usr/local/bin/docker-entrypoint.sh node /opt/lark-mcp-auth/start.mjs
```

Keep public networking pointed at `PORT` (3000). Do not expose `MCP_INTERNAL_PORT` (defaults to 3001). Optional readiness healthcheck: `/healthz`.

## Auth0 setup

Follow Auth0's MCP setup guide: https://auth0.com/ai/docs/mcp/get-started/authorization-for-your-mcp-server

Enable Resource Parameter Compatibility Profile and Include Issuer in Authorization Responses. Configure a login connection usable by the chosen OAuth client. Use CIMD or DCR if configured in Auth0; otherwise register a static public OAuth client with authorization code + PKCE and the exact redirect URI shown by the desktop plugin. Never invent or allow wildcard callback URIs.

The gateway publishes protected resource metadata at `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource`. OAuth discovery, authorization and token exchange are handled by Auth0. Requested OIDC scopes are `openid profile email`; the API audience/resource is the exact MCP URL.

The allowlisted email must correspond to an actual application login, not just an Auth0 dashboard administrator. A Google login with the verified allowlisted email or a verified Auth0 database login may be used. Do not grant other accounts access to the MCP.

Choose OAuth in the desktop plugin and reconnect. Verify that anonymous requests get HTTP 401, an approved login can list all configured tools, and an unapproved account cannot call the upstream service. Email authorization caching is limited to 60 seconds and never extends the token expiration.

Run tests with `npm ci` and `npm test` in this folder. Tests use locally generated RSA keys, a fake UserInfo response, and a mock MCP backend; no real credentials or tasks are used.
