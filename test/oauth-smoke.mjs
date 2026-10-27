import assert from "node:assert/strict";
import { oauthRoute, verifyAccessToken, oauthResource } from "../src/oauth.js";
import worker from "../src/index.js";

class MemoryD1 {
  tables = { clients: new Map(), pending: new Map(), codes: new Map(), access: new Map(), refresh: new Map(), replays: new Map(), dcr: new Map(), attempts: [] };
  batchTail = Promise.resolve();
  prepare(sql) {
    const self = this; let args = [];
    const stmt = {
      bind(...values) { args = values; return this; },
      async first() {
        const a = args;
        if (sql.includes("DELETE FROM oauth_pending") && sql.includes("RETURNING")) { const x=self.tables.pending.get(a[0]); if(x && x.expires_at>=a[1]) { self.tables.pending.delete(a[0]); return x; } return null; }
        if (sql.includes("FROM oauth_clients WHERE client_id")) return self.tables.clients.get(a[0]) || null;
        if (sql.includes("FROM oauth_pending WHERE handle")) return self.tables.pending.get(a[0]) || null;
        if (sql.includes("FROM oauth_codes WHERE code_hash")) return self.tables.codes.get(a[0]) || null;
        if (sql.includes("FROM oauth_access WHERE token_hash")) return self.tables.access.get(a[0]) || null;
        if (sql.includes("FROM oauth_refresh WHERE token_hash")) return self.tables.refresh.get(a[0]) || null;
        if (sql.includes("FROM oauth_refresh_replays WHERE token_hash")) { const x=self.tables.replays.get(a[0]); return x?.client_id===a[1] && x.expires_at>=a[2] ? x : null; }
        if (sql.includes("INSERT INTO oauth_dcr_limits") && sql.includes("ON CONFLICT")) { const k=`${a[0]}:${a[1]}`, x=self.tables.dcr.get(k); if(x?.count>=10)return null; const count=(x?.count||0)+1; self.tables.dcr.set(k,{ip_hash:a[0],window_start:a[1],count}); return {count}; }
        if (sql.includes("COUNT(*) AS n FROM oauth_clients")) return { n: self.tables.clients.size };
        if (sql.includes("COUNT(*) AS n")) return { n: self.tables.attempts.filter((x) => x.ip_hash === a[0] && x.attempted_at >= a[1]).length };
        return null;
      },
      async run() {
        const a = args;
        if (sql.includes("INSERT INTO oauth_clients")) self.tables.clients.set(a[0], { client_id: a[0], client_secret_hash: a[1], auth_method: a[2], redirect_uris: a[3], client_name: a[4], created_at: a[5] });
        else if (sql.includes("INSERT INTO oauth_pending")) self.tables.pending.set(a[0], { payload: a[1], expires_at: a[2] });
        else if (sql.includes("INSERT INTO oauth_codes")) self.tables.codes.set(a[0], { payload: a[1], expires_at: a[2] });
        else if (sql.includes("INSERT INTO oauth_access") && sql.includes("SELECT ?")) { if(self.tables.replays.get(a[6])?.consumer_id===a[7]) self.tables.access.set(a[0], { family_id:a[1], client_id: a[2], resource: a[3], scope: a[4], expires_at: a[5] }); }
        else if (sql.includes("INSERT INTO oauth_access")) self.tables.access.set(a[0], { family_id:a[1], client_id: a[2], resource: a[3], scope: a[4], expires_at: a[5] });
        else if (sql.includes("INSERT INTO oauth_refresh_replays")) { const row=self.tables.refresh.get(a[1]); if(row && !self.tables.replays.has(a[1])) self.tables.replays.set(a[1],{family_id:row.family_id,client_id:row.client_id,expires_at:row.expires_at,consumer_id:a[0]}); }
        else if (sql.includes("INSERT INTO oauth_refresh") && sql.includes("SELECT ?")) { if(self.tables.replays.get(a[6])?.consumer_id===a[7]) self.tables.refresh.set(a[0], { family_id:a[1], client_id: a[2], resource: a[3], scope: a[4], expires_at: a[5] }); }
        else if (sql.includes("INSERT INTO oauth_refresh")) self.tables.refresh.set(a[0], { family_id:a[1], client_id: a[2], resource: a[3], scope: a[4], expires_at: a[5] });
        else if (sql.includes("INSERT INTO oauth_login_attempts")) self.tables.attempts.push({ ip_hash: a[0], attempted_at: a[1] });
        else if (sql.includes("DELETE FROM oauth_pending")) return { meta: { changes: Number(self.tables.pending.delete(a[0])) } };
        else if (sql.includes("DELETE FROM oauth_codes")) return { meta: { changes: Number(self.tables.codes.delete(a[0])) } };
        else if (sql.includes("DELETE FROM oauth_access WHERE family_id")) { let n=0; for(const [k,v] of self.tables.access) if(v.family_id===a[0]) {self.tables.access.delete(k);n++} return {meta:{changes:n}}; }
        else if (sql.includes("DELETE FROM oauth_refresh WHERE family_id")) { let n=0; for(const [k,v] of self.tables.refresh) if(v.family_id===a[0]) {self.tables.refresh.delete(k);n++} return {meta:{changes:n}}; }
        else if (sql.includes("DELETE FROM oauth_refresh")) return { meta: { changes: Number(self.tables.refresh.delete(a[0])) } };
        else if (sql.includes("DELETE FROM oauth_dcr_limits")) { for(const [k,x] of self.tables.dcr) if(x.window_start<a[0]) self.tables.dcr.delete(k); }
        else if (sql.includes("DELETE FROM oauth_login_attempts")) self.tables.attempts = self.tables.attempts.filter((x) => x.attempted_at >= a[0]);
        return { meta: { changes: 1 } };
      },
    };
    return stmt;
  }
  async batch(stmts) { let release; const previous=this.batchTail; this.batchTail=new Promise(resolve=>release=resolve); await previous; try { const out=[]; for (const s of stmts) out.push(await s.run()); return out; } finally { release(); } }
}

const db = new MemoryD1();
const env = { OAUTH_DB: db, MCP_AUTH_TOKEN: "test-admin-token", OAUTH_ISSUER: "https://weread.example.test", OAUTH_USERNAME: "owner", OAUTH_PASSWORD: "test-password" };
const req = (path, init = {}) => new Request("https://weread.example.test" + path, init);

let res = await oauthRoute(req("/.well-known/oauth-protected-resource/mcp"), env, new URL("https://weread.example.test/.well-known/oauth-protected-resource/mcp"));
assert.equal(res.status, 200);
assert.deepEqual((await res.json()).authorization_servers, [env.OAUTH_ISSUER]);
const canonicalEnv = { ...env, OAUTH_ISSUER: "https://oauth.canonical.example/" };
res = await oauthRoute(req("/.well-known/oauth-protected-resource/mcp"), canonicalEnv, new URL("https://weread.example.test/.well-known/oauth-protected-resource/mcp"));
assert.equal((await res.json()).resource, "https://oauth.canonical.example/mcp", "discovery must use configured canonical issuer, not request Host");
assert.equal(oauthResource(canonicalEnv, req("/mcp")), "https://oauth.canonical.example/mcp", "MCP validation must use the same canonical resource");
await assert.rejects(() => oauthRoute(req("/.well-known/oauth-authorization-server"), { ...env, OAUTH_ISSUER: "https://oauth.canonical.example/path" }, new URL("https://weread.example.test/.well-known/oauth-authorization-server")), /OAUTH_ISSUER/);

res = await oauthRoute(req("/.well-known/oauth-authorization-server"), env, new URL("https://weread.example.test/.well-known/oauth-authorization-server"));
const metadata = await res.json();
assert.equal(metadata.code_challenge_methods_supported[0], "S256");
assert.ok(metadata.scopes_supported.includes("offline_access"));

res = await oauthRoute(req("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client.example/callback#fragment"] }) }), env, new URL("https://weread.example.test/register"));
assert.equal(res.status, 400, "redirect URI fragments must be rejected");
res = await oauthRoute(req("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "ChatGPT test", redirect_uris: ["https://client.example/callback"], token_endpoint_auth_method: "none" }) }), env, new URL("https://weread.example.test/register"));
assert.equal(res.status, 201);
const client = await res.json();
for (let i = 0; i < 9; i++) {
  const limited = await oauthRoute(req("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: [`https://client${i}.example/callback`] }) }), env, new URL("https://weread.example.test/register"));
  assert.equal(limited.status, 201);
}
res = await oauthRoute(req("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client-limit.example/callback"] }) }), env, new URL("https://weread.example.test/register"));
assert.equal(res.status, 429, "DCR must rate limit a source after 10 registrations per 15 minutes");

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
const pendingRace = await Promise.all([1, 2].map(() => oauthRoute(req("/authorize", { method: "POST", headers: { cookie: `oauth_pending=${handle}`, "content-type": "application/x-www-form-urlencoded" }, body: form }), env, new URL("https://weread.example.test/authorize"))));
assert.deepEqual(pendingRace.map(x => x.status).sort(), [302, 400], "pending handle must have exactly one successful concurrent submission");
res = pendingRace.find(x => x.status === 302);
const callback = new URL(res.headers.get("location"));
assert.equal(callback.searchParams.get("state"), "state-123");
assert.equal(callback.searchParams.get("iss"), env.OAUTH_ISSUER);
const code = callback.searchParams.get("code");

const denyUrl = new URL(authUrl); denyUrl.searchParams.set("state", "deny-state");
res = await oauthRoute(req(denyUrl.pathname + denyUrl.search), env, denyUrl);
const denyHandle = res.headers.get("set-cookie").match(/oauth_pending=([^;]+)/)[1];
const denyForm = new URLSearchParams({ handle: denyHandle, approve: "no" });
res = await oauthRoute(req("/authorize", { method: "POST", headers: { cookie: `oauth_pending=${denyHandle}`, "content-type": "application/x-www-form-urlencoded" }, body: denyForm }), env, new URL("https://weread.example.test/authorize"));
const denied = new URL(res.headers.get("location"));
assert.equal(denied.searchParams.get("error"), "access_denied");
assert.equal(denied.searchParams.get("state"), "deny-state");

const tokenForm = new URLSearchParams({ grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: "https://client.example/callback", resource: "https://weread.example.test/mcp", code_verifier: verifier });
const wrongResourceForm = new URLSearchParams(tokenForm); wrongResourceForm.set("resource", "https://attacker.example/mcp");
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: wrongResourceForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "token resource must match the authorization request");
const codeRace = await Promise.all([1, 2].map(() => oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenForm }), env, new URL("https://weread.example.test/token"))));
assert.deepEqual(codeRace.map(x => x.status).sort(), [200, 400], "authorization code must have exactly one concurrent consumer");
const tokens = await codeRace.find(x => x.status === 200).json();
assert.ok(tokens.refresh_token);
assert.equal(await verifyAccessToken(req("/mcp", { headers: { authorization: `Bearer ${tokens.access_token}` } }), env, "https://weread.example.test/mcp"), true);
assert.equal(await verifyAccessToken(req("/mcp", { headers: { authorization: `Bearer ${tokens.access_token}` } }), env, "https://attacker.example/mcp"), false);
const mcpRequest = (path, init = {}) => worker.fetch(new Request("https://weread.example.test" + path, init), env);
res = await mcpRequest("/mcp", { method: "POST", headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "oauth-test", version: "1" } } }) });
assert.equal(res.status, 200, "valid OAuth token must reach /mcp before replay detection");

res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: tokenForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "authorization code must be single use");

const refreshForm = new URLSearchParams({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.refresh_token });
const wrongRefreshResource = new URLSearchParams(refreshForm); wrongRefreshResource.set("resource", "https://attacker.example/mcp");
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: wrongRefreshResource }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "refresh resource must not be rebound to another audience");
const refreshRace = await Promise.all([1, 2].map(() => oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: refreshForm }), env, new URL("https://weread.example.test/token"))));
assert.deepEqual(refreshRace.map(x => x.status).sort(), [200, 400], "refresh token must have exactly one concurrent consumer");
const rotated = await refreshRace.find(x => x.status === 200).json();
assert.notEqual(rotated.refresh_token, tokens.refresh_token);
assert.equal(await verifyAccessToken(req("/mcp", { headers: { authorization: `Bearer ${rotated.access_token}` } }), env, "https://weread.example.test/mcp"), false, "concurrent refresh replay must revoke the entire token family");
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: refreshForm }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "refresh token must rotate once");
assert.equal(await verifyAccessToken(req("/mcp", { headers: { authorization: `Bearer ${rotated.access_token}` } }), env, "https://weread.example.test/mcp"), false, "refresh replay must revoke the token family");
const rotatedReplay = new URLSearchParams({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: rotated.refresh_token });
res = await oauthRoute(req("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: rotatedReplay }), env, new URL("https://weread.example.test/token"));
assert.equal(res.status, 400, "revoked token family must reject its rotated refresh token");


res = await mcpRequest("/dashboard", { headers: { authorization: `Bearer ${tokens.access_token}` } });
assert.equal(res.status, 403, "OAuth token must not grant dashboard access");
res = await mcpRequest("/coread", { headers: { authorization: `Bearer ${tokens.access_token}` } });
assert.equal(res.status, 401, "OAuth token must not grant coread management access");
res = await mcpRequest("/mcp", { method: "POST", headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "oauth-test", version: "1" } } }) });
assert.equal(res.status, 401, "refresh-token replay must revoke its family at /mcp");
res = await mcpRequest("/mcp", { method: "POST", headers: { authorization: "Bearer invalid-token", "content-type": "application/json", accept: "application/json, text/event-stream" }, body: "{}" });
assert.equal(res.status, 401);
assert.match(res.headers.get("www-authenticate") || "", /oauth-protected-resource/);
console.log("OAuth discovery, DCR, PKCE, one-use codes, resource binding, refresh rotation, and management boundary passed.");

