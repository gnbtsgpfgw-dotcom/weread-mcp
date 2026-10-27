import assert from "node:assert/strict";
import { oauthRoute, verifyAccessToken } from "../src/oauth.js";
import worker from "../src/index.js";

class MemoryD1 {
  tables = { clients: new Map(), pending: new Map(), codes: new Map(), access: new Map(), refresh: new Map(), attempts: [] };
  prepare(sql) {
    const self = this; let args = [];
    const stmt = {
      bind(...values) { args = values; return this; },
      async first() {
        const a = args;
        if (sql.includes("FROM oauth_clients WHERE client_id")) return self.tables.clients.get(a[0]) || null;
        if (sql.includes("FROM oauth_pending WHERE handle")) return self.tables.pending.get(a[0]) || null;
        if (sql.includes("FROM oauth_codes WHERE code_hash")) return self.tables.codes.get(a[0]) || null;
        if (sql.includes("FROM oauth_access WHERE token_hash")) return self.tables.access.get(a[0]) || null;
        if (sql.includes("FROM oauth_refresh WHERE token_hash")) return self.tables.refresh.get(a[0]) || null;
        if (sql.includes("COUNT(*) AS n")) return { n: self.tables.attempts.filter((x) => x.ip_hash === a[0] && x.attempted_at >= a[1]).length };
        return null;
      },
      async run() {
        const a = args;
        if (sql.includes("INSERT INTO oauth_clients")) self.tables.clients.set(a[0], { client_id: a[0], client_secret_hash: a[1], auth_method: a[2], redirect_uris: a[3], client_name: a[4], created_at: a[5] });
        else if (sql.includes("INSERT INTO oauth_pending")) self.tables.pending.set(a[0], { payload: a[1], expires_at: a[2] });
        else if (sql.includes("INSERT INTO oauth_codes")) self.tables.codes.set(a[0], { payload: a[1], expires_at: a[2] });
        else if (sql.includes("INSERT INTO oauth_access")) self.tables.access.set(a[0], { client_id: a[1], resource: a[2], scope: a[3], expires_at: a[4] });
        else if (sql.includes("INSERT INTO oauth_refresh")) self.tables.refresh.set(a[0], { client_id: a[1], resource: a[2], scope: a[3], expires_at: a[4] });
        else if (sql.includes("INSERT INTO oauth_login_attempts")) self.tables.attempts.push({ ip_hash: a[0], attempted_at: a[1] });
        else if (sql.includes("DELETE FROM oauth_pending")) return { meta: { changes: Number(self.tables.pending.delete(a[0])) } };
        else if (sql.includes("DELETE FROM oauth_codes")) return { meta: { changes: Number(self.tables.codes.delete(a[0])) } };
        else if (sql.includes("DELETE FROM oauth_refresh")) return { meta: { changes: Number(self.tables.refresh.delete(a[0])) } };
        else if (sql.includes("DELETE FROM oauth_login_attempts")) self.tables.attempts = self.tables.attempts.filter((x) => x.attempted_at >= a[0]);
        return { meta: { changes: 1 } };
      },
    };
    return stmt;
  }
  async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; }
}

const db = new MemoryD1();
const env = { OAUTH_DB: db, MCP_AUTH_TOKEN: "test-admin-token", OAUTH_ISSUER: "https://weread.example.test", OAUTH_USERNAME: "owner", OAUTH_PASSWORD: "test-password" };
const req = (path, init = {}) => new Request("https://weread.example.test" + path, init);

let res = await oauthRoute(req("/.well-known/oauth-protected-resource/mcp"), env, new URL("https://weread.example.test/.well-known/oauth-protected-resource/mcp"));
assert.equal(res.status, 200);
assert.deepEqual((await res.json()).authorization_servers, [env.OAUTH_ISSUER]);

res = await oauthRoute(req("/.well-known/oauth-authorization-server"), env, new URL("https://weread.example.test/.well-known/oauth-authorization-server"));
const metadata = await res.json();
assert.equal(metadata.code_challenge_methods_supported[0], "S256");
assert.ok(metadata.scopes_supported.includes("offline_access"));

res = await oauthRoute(req("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "ChatGPT test", redirect_uris: ["https://client.example/callback"], token_endpoint_auth_method: "none" }) }), env, new URL("https://weread.example.test/register"));
assert.equal(res.status, 201);
const client = await res.json();

const verifier = "a".repeat(43);
const challenge = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
const challengeText = btoa(String.fromCharCode(...new Uint8Array(challenge))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const authUrl = new URL("https://weread.example.test/authorize");
for (const [k, v] of Object.entries({ response_type: "code", client_id: client.client_id, redirect_uri: "https://client.example/callback", state: "state-123", code_challenge: challengeText, code_challenge_method: "S256", resource: "https://weread.example.test/mcp", scope: "weread offline_access" })) authUrl.searchParams.set(k, v);
res = await oauthRoute(req(authUrl.pathname + authUrl.search), env, authUrl);
assert.equal(res.status, 200);
const setCookie = res.headers.get("set-cookie");
const handle = setCookie.match(/oauth_pending=([^;]+)/)[1];
const formHtml = await res.text();
assert.ok(formHtml.includes("ChatGPT test"));
const form = new URLSearchParams({ handle, username: "owner", password: "test-password", approve: "yes" });
res = await oauthRoute(req("/authorize", { method: "POST", headers: { cookie: `oauth_pending=${handle}`, "content-type": "application/x-www-form-urlencoded" }, body: form }), env, new URL("https://weread.example.test/authorize"));
assert.equal(res.status, 302);
const callback = new URL(res.headers.get("location"));
assert.equal(callback.searchParams.get("state"), "state-123");
assert.equal(callback.searchParams.get("iss"), env.OAUTH_ISSUER);
const code = callback.searchParams.get("code");

const tokenForm = new URLSearchParams({ grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: "https://client.example/callback", resource: "https://weread.example.test/mcp", code_verifier: verifier });
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 200);
const tokens = await res.json();
assert.ok(tokens.refresh_token);
assert.equal(await verifyAccessToken(req("/mcp", { headers: { authorization: `Bearer ${tokens.access_token}` } }), env, "https://weread.example.test/mcp"), true);
assert.equal(await verifyAccessToken(req("/mcp", { headers: { authorization: `Bearer ${tokens.access_token}` } }), env, "https://attacker.example/mcp"), false);

res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "authorization code must be single use");

const refreshForm = new URLSearchParams({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.refresh_token });
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: refreshForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 200);
const rotated = await res.json();
assert.notEqual(rotated.refresh_token, tokens.refresh_token);
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: refreshForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "refresh token must rotate once");


const mcpRequest = (path, init = {}) => worker.fetch(new Request("https://weread.example.test" + path, init), env);
res = await mcpRequest("/dashboard", { headers: { authorization: `Bearer ${tokens.access_token}` } });
assert.equal(res.status, 403, "OAuth token must not grant dashboard access");
res = await mcpRequest("/coread", { headers: { authorization: `Bearer ${tokens.access_token}` } });
assert.equal(res.status, 401, "OAuth token must not grant coread management access");
res = await mcpRequest("/mcp", { method: "POST", headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "oauth-test", version: "1" } } }) });
assert.equal(res.status, 200, "valid OAuth token must reach /mcp");
res = await mcpRequest("/mcp", { method: "POST", headers: { authorization: "Bearer invalid-token", "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
assert.equal(res.status, 401);
assert.match(res.headers.get("www-authenticate") || "", /oauth-protected-resource/);
\nconsole.log("OAuth discovery, DCR, PKCE, one-use codes, resource binding, refresh rotation, and management boundary passed.");
