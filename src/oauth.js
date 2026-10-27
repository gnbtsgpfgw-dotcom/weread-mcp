const ACCESS_TTL = 900;
const CODE_TTL = 300;
const REFRESH_TTL = 2592000;
const SCOPE = "weread";
const enc = new TextEncoder();
const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const random = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b64url(b); };
const hash = async (s) => b64url(await crypto.subtle.digest("SHA-256", enc.encode(String(s))));
const now = () => Math.floor(Date.now() / 1000);
const db = (env) => { if (!env.OAUTH_DB) throw new Error("OAuth D1 binding OAUTH_DB is required"); return env.OAUTH_DB; };
const json = (v, status = 200, headers = {}) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", pragma: "no-cache", ...headers } });
const err = (error, status = 400, headers = {}) => json({ error }, status, headers);
const same = (a, b) => { const x = enc.encode(String(a)); const y = enc.encode(String(b)); if (x.length !== y.length) return false; let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i]; return d === 0; };
export function issuerOf(env, request) {
  const value = String(env.OAUTH_ISSUER || new URL(request.url).origin);
  const parsed = new URL(value);
  if (parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username || parsed.password || parsed.origin !== value.replace(/\/$/, "") || (env.OAUTH_ISSUER && parsed.protocol !== "https:")) throw new Error("OAUTH_ISSUER must be a canonical HTTPS origin without a path, query, or fragment");
  return parsed.origin;
}
const resourceOf = (env, request) => issuerOf(env, request) + "/mcp";
export const oauthResource = resourceOf;
const protectedMetadata = (env, request) => ({
  resource: resourceOf(env, request),
  authorization_servers: [issuerOf(env, request)],
  bearer_methods_supported: ["header"],
  scopes_supported: [SCOPE],
});
const authMetadata = (env, request) => {
  const iss = issuerOf(env, request);
  return {
    issuer: iss,
    authorization_endpoint: iss + "/authorize",
    token_endpoint: iss + "/token",
    registration_endpoint: iss + "/register",
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [SCOPE, "offline_access"],
    authorization_response_iss_parameter_supported: true,
  };
};
const html = (s, status = 200, headers = {}) => new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Weread MCP authorization</title></head><body>${s}</body></html>`, {
  status,
  headers: {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    ...headers,
  },
});
const cookie = (request, name) => {
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return "";
};
const clearPendingCookie = "oauth_pending=; HttpOnly; Secure; SameSite=Lax; Path=/authorize; Max-Age=0";
function safeRedirect(uri, values) {
  const out = new URL(uri);
  for (const [k, v] of Object.entries(values)) if (v != null) out.searchParams.set(k, String(v));
  return Response.redirect(out.toString(), 302);
}
function validRedirect(uri) {
  try {
    const u = new URL(uri);
    const hostAllowed = u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
    return hostAllowed && !u.username && !u.password && !u.hash;
  } catch { return false; }
}
async function readClient(dbx, clientId) {
  return dbx.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(clientId).first();
}
async function register(request, env) {
  if (request.method !== "POST") return err("invalid_request", 405);
  let m;
  let raw;
  try { raw = await request.text(); } catch { return err("invalid_client_metadata"); }
  if (raw.length > 16384) return err("invalid_client_metadata");
  try { m = JSON.parse(raw); } catch { return err("invalid_client_metadata"); }
  if (!Array.isArray(m.redirect_uris) || !m.redirect_uris.length || m.redirect_uris.length > 20 || m.redirect_uris.some((u) => typeof u !== "string" || !validRedirect(u))) return err("invalid_redirect_uri");
  if (m.grant_types && (!Array.isArray(m.grant_types) || m.grant_types.some((v) => !["authorization_code", "refresh_token"].includes(v)))) return err("invalid_client_metadata");
  if (m.response_types && (!Array.isArray(m.response_types) || m.response_types.some((v) => v !== "code"))) return err("invalid_client_metadata");
  const method = m.token_endpoint_auth_method || "none";
  if (!["none", "client_secret_basic", "client_secret_post"].includes(method)) return err("invalid_client_metadata");
  const ipHash = await hash(request.headers.get("CF-Connecting-IP") || "unknown");
  const d = db(env);
  const windowStart = Math.floor(now() / 900) * 900;
  await d.prepare("DELETE FROM oauth_dcr_limits WHERE window_start < ?").bind(windowStart).run();
  const allowed = await d.prepare("INSERT INTO oauth_dcr_limits(ip_hash,window_start,count) VALUES(?,?,1) ON CONFLICT(ip_hash,window_start) DO UPDATE SET count=count+1 WHERE count<10 RETURNING count").bind(ipHash, windowStart).first();
  if (!allowed) return err("temporarily_unavailable", 429, { "retry-after": "900" });
  const total = await d.prepare("SELECT COUNT(*) AS n FROM oauth_clients").first();
  if ((total?.n || 0) >= 5000) return err("temporarily_unavailable", 503);
  const clientId = random(24);
  const clientSecret = method === "none" ? null : random(32);
  const redirects = [...new Set(m.redirect_uris)];
  await db(env).prepare("INSERT INTO oauth_clients(client_id, client_secret_hash, auth_method, redirect_uris, client_name, created_at) VALUES(?,?,?,?,?,?)")
    .bind(clientId, clientSecret ? await hash(clientSecret) : null, method, JSON.stringify(redirects), String(m.client_name || "").slice(0, 100), now()).run();
  return json({
    client_id: clientId,
    ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
    client_id_issued_at: now(),
    redirect_uris: redirects,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: method,
  }, 201);
}
async function parseAuthorizeRequest(request, env, url) {
  const p = url.searchParams;
  const dbx = db(env);
  const client = await readClient(dbx, p.get("client_id") || "");
  const redirectUri = p.get("redirect_uri") || "";
  const challenge = p.get("code_challenge") || "";
  const scope = (p.get("scope") || SCOPE).split(/\s+/).filter(Boolean);
  if (!client || !JSON.parse(client.redirect_uris).includes(redirectUri) || !validRedirect(redirectUri)) return null;
  if (p.get("response_type") !== "code" || !p.get("state") || p.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) return null;
  if (p.get("resource") !== resourceOf(env, request) || scope.some((s) => ![SCOPE, "offline_access"].includes(s))) return null;
  return { client_id: client.client_id, client_name: client.client_name || "OAuth client", redirect_uri: redirectUri, state: p.get("state"), challenge, resource: p.get("resource"), scope: [...new Set(scope)].join(" ") };
}
async function authorize(request, env, url) {
  const dbx = db(env);
  if (request.method === "GET") {
    const pending = await parseAuthorizeRequest(request, env, url);
    if (!pending) return html("<h1>Invalid authorization request</h1><p>Restart the connection from ChatGPT.</p>", 400);
    const handle = random();
    await dbx.prepare("INSERT INTO oauth_pending(handle,payload,expires_at) VALUES(?,?,?)").bind(handle, JSON.stringify(pending), now() + CODE_TTL).run();
    const redirect = new URL(pending.redirect_uri);
    return html(`<main><h1>Authorize Weread MCP</h1><p>Client: <strong>${escapeHtml(pending.client_name)}</strong></p><p>Requested access: <code>${escapeHtml(pending.scope)}</code></p><p>Redirect destination: <code>${escapeHtml(redirect.origin + redirect.pathname)}</code></p><form method="post" action="/authorize"><input type="hidden" name="handle" value="${handle}"><label>OAuth username <input name="username" autocomplete="username" required></label><br><label>OAuth password <input type="password" name="password" autocomplete="current-password" required></label><br><button name="approve" value="yes">Sign in and authorize</button><button name="approve" value="no" formnovalidate>拒绝</button></form></main>`, 200, { "set-cookie": `oauth_pending=${handle}; HttpOnly; Secure; SameSite=Lax; Path=/authorize; Max-Age=${CODE_TTL}` });
  }
  if (request.method !== "POST") return err("invalid_request", 405);
  let fields;
  try { fields = Object.fromEntries(await request.formData()); } catch { return html("<h1>Invalid request</h1>", 400); }
  const handle = String(fields.handle || "");
  if (!handle || !same(handle, cookie(request, "oauth_pending"))) return html("<h1>Authorization session expired</h1><p>Restart the connection from ChatGPT.</p>", 400, { "set-cookie": clearPendingCookie });
  const pendingRow = await dbx.prepare("SELECT payload,expires_at FROM oauth_pending WHERE handle=?").bind(handle).first();
  if (!pendingRow || pendingRow.expires_at < now()) return html("<h1>Authorization session expired</h1><p>Restart the connection from ChatGPT.</p>", 400, { "set-cookie": clearPendingCookie });
  if (fields.approve !== "yes") {
    const denied = await dbx.prepare("DELETE FROM oauth_pending WHERE handle=? AND expires_at>=? RETURNING payload").bind(handle, now()).first();
    if (!denied) return html("<h1>Authorization session expired</h1><p>Restart the connection from ChatGPT.</p>", 400, { "set-cookie": clearPendingCookie });
    const payload = JSON.parse(denied.payload);
    return safeRedirect(payload.redirect_uri, { error: "access_denied", state: payload.state, iss: issuerOf(env, request) });
  }
  if (!env.OAUTH_USERNAME || !env.OAUTH_PASSWORD) return html("<h1>OAuth login is not configured</h1>", 503, { "set-cookie": clearPendingCookie });
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await hash(ip);
  await dbx.prepare("DELETE FROM oauth_login_attempts WHERE attempted_at < ?").bind(now() - 900).run();
  const count = await dbx.prepare("SELECT COUNT(*) AS n FROM oauth_login_attempts WHERE ip_hash=? AND attempted_at>=?").bind(ipHash, now() - 900).first();
  if ((count?.n || 0) >= 10) return html("<h1>Too many attempts</h1><p>Wait 15 minutes and restart.</p>", 429, { "set-cookie": clearPendingCookie });
  if (!same(fields.username, env.OAUTH_USERNAME) || !same(fields.password, env.OAUTH_PASSWORD)) {
    await dbx.prepare("INSERT INTO oauth_login_attempts(ip_hash,attempted_at) VALUES(?,?)").bind(ipHash, now()).run();
    return html("<h1>Sign-in failed</h1><p>Check the configured OAuth account and try again.</p>", 401, { "set-cookie": clearPendingCookie });
  }
  const consumed = await dbx.prepare("DELETE FROM oauth_pending WHERE handle=? AND expires_at>=? RETURNING payload").bind(handle, now()).first();
  if (!consumed) return html("<h1>Authorization session expired</h1><p>Restart the connection from ChatGPT.</p>", 400, { "set-cookie": clearPendingCookie });
  const payload = JSON.parse(consumed.payload);
  const code = random(32);
  await dbx.prepare("INSERT INTO oauth_codes(code_hash,payload,expires_at) VALUES(?,?,?)").bind(await hash(code), JSON.stringify(payload), now() + CODE_TTL).run();
  return safeRedirect(payload.redirect_uri, { code, state: payload.state, iss: issuerOf(env, request) });
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]); }
async function clientAuth(request, body, env) {
  let id = String(body.client_id || ""), secret = String(body.client_secret || "");
  const header = request.headers.get("authorization") || "";
  const basic = header.startsWith("Basic ");
  if (header && !basic) return null;
  if (basic) {
    try {
      const decoded = atob(header.slice(6));
      const i = decoded.indexOf(":");
      if (i < 0) return null;
      id = decodeURIComponent(decoded.slice(0, i).replace(/\+/g, " "));
      secret = decodeURIComponent(decoded.slice(i + 1).replace(/\+/g, " "));
    } catch { return null; }
  }
  const client = await readClient(db(env), id);
  if (!client) return null;
  if (client.auth_method === "none") return !basic && !secret ? client : null;
  if (client.auth_method === "client_secret_basic" && !basic) return null;
  if (client.auth_method === "client_secret_post" && basic) return null;
  if (!secret || !client.client_secret_hash || !same(await hash(secret), client.client_secret_hash)) return null;
  return client;
}
async function issueTokens(env, clientId, resource, scope, familyId = random()) {
  const dbx = db(env), accessToken = random(32), refreshToken = random(40), t = now();
  await dbx.batch([
    dbx.prepare("INSERT INTO oauth_access(token_hash,family_id,client_id,resource,scope,expires_at) VALUES(?,?,?,?,?,?)").bind(await hash(accessToken), familyId, clientId, resource, scope, t + ACCESS_TTL),
    dbx.prepare("INSERT INTO oauth_refresh(token_hash,family_id,client_id,resource,scope,expires_at) VALUES(?,?,?,?,?,?)").bind(await hash(refreshToken), familyId, clientId, resource, scope, t + REFRESH_TTL),
  ]);
  return json({ access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refreshToken, scope });
}
async function token(request, env) {
  if (request.method !== "POST") return err("invalid_request", 405);
  let fields;
  try {
    if ((request.headers.get("content-type") || "").startsWith("application/json")) fields = await request.json();
    else fields = Object.fromEntries(await request.formData());
  } catch { return err("invalid_request"); }
  const client = await clientAuth(request, fields, env);
  if (!client) return err("invalid_client", 401);
  if (fields.grant_type === "authorization_code") {
    const codeHash = await hash(fields.code || "");
    const row = await db(env).prepare("SELECT payload,expires_at FROM oauth_codes WHERE code_hash=?").bind(codeHash).first();
    if (!row || row.expires_at < now()) return err("invalid_grant");
    const p = JSON.parse(row.payload);
    if (p.client_id !== client.client_id || p.redirect_uri !== fields.redirect_uri || p.resource !== fields.resource || !/^[A-Za-z0-9._~-]{43,128}$/.test(fields.code_verifier || "") || await hash(fields.code_verifier) !== p.challenge) return err("invalid_grant");
    const deleted = await db(env).prepare("DELETE FROM oauth_codes WHERE code_hash=? AND expires_at>=?").bind(codeHash, now()).run();
    if (!deleted.meta?.changes) return err("invalid_grant");
    return issueTokens(env, client.client_id, p.resource, p.scope);
  }
  if (fields.grant_type === "refresh_token") {
    const tokenHash = await hash(fields.refresh_token || "");
    const dbx = db(env);
    const row = await dbx.prepare("SELECT family_id,client_id,resource,scope,expires_at FROM oauth_refresh WHERE token_hash=?").bind(tokenHash).first();
    if (!row) {
      const replay = await dbx.prepare("SELECT family_id FROM oauth_refresh_replays WHERE token_hash=? AND client_id=? AND expires_at>=?").bind(tokenHash, client.client_id, now()).first();
      if (replay) await dbx.batch([
        dbx.prepare("DELETE FROM oauth_access WHERE family_id=?").bind(replay.family_id),
        dbx.prepare("DELETE FROM oauth_refresh WHERE family_id=?").bind(replay.family_id),
      ]);
      return err("invalid_grant");
    }
    if (row.client_id !== client.client_id || row.expires_at < now() || (fields.resource && fields.resource !== row.resource)) return err("invalid_grant");
    const consumerId = random(), accessToken = random(32), refreshToken = random(40), t = now();
    const accessHash = await hash(accessToken), refreshHash = await hash(refreshToken);
    const result = await dbx.batch([
      dbx.prepare("INSERT INTO oauth_refresh_replays(token_hash,family_id,client_id,expires_at,consumer_id) SELECT token_hash,family_id,client_id,expires_at,? FROM oauth_refresh WHERE token_hash=? ON CONFLICT(token_hash) DO NOTHING").bind(consumerId, tokenHash),
      dbx.prepare("DELETE FROM oauth_refresh WHERE token_hash=? AND expires_at>=?").bind(tokenHash, now()),
      dbx.prepare("INSERT INTO oauth_access(token_hash,family_id,client_id,resource,scope,expires_at) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM oauth_refresh_replays WHERE token_hash=? AND consumer_id=?)").bind(accessHash, row.family_id, row.client_id, row.resource, row.scope, t + ACCESS_TTL, tokenHash, consumerId),
      dbx.prepare("INSERT INTO oauth_refresh(token_hash,family_id,client_id,resource,scope,expires_at) SELECT ?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM oauth_refresh_replays WHERE token_hash=? AND consumer_id=?)").bind(refreshHash, row.family_id, row.client_id, row.resource, row.scope, t + REFRESH_TTL, tokenHash, consumerId),
    ]);
    if (!result[1]?.meta?.changes) {
      const replay = await dbx.prepare("SELECT family_id FROM oauth_refresh_replays WHERE token_hash=? AND client_id=? AND expires_at>=?").bind(tokenHash, client.client_id, now()).first();
      if (replay) await dbx.batch([
        dbx.prepare("DELETE FROM oauth_access WHERE family_id=?").bind(replay.family_id),
        dbx.prepare("DELETE FROM oauth_refresh WHERE family_id=?").bind(replay.family_id),
      ]);
      return err("invalid_grant");
    }
    return json({ access_token: accessToken, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refreshToken, scope: row.scope });
  }
  return err("unsupported_grant_type");
}
export async function oauthRoute(request, env, url) {
  const path = url.pathname;
  if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") return json(protectedMetadata(env, request));
  if (path === "/.well-known/oauth-authorization-server") return json(authMetadata(env, request));
  if (path === "/register") return register(request, env);
  if (path === "/authorize") return authorize(request, env, url);
  if (path === "/token") return token(request, env);
  return null;
}
export async function verifyAccessToken(request, env, expectedResource) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ") || !env.OAUTH_DB) return false;
  const raw = header.slice(7);
  if (!raw || raw.length > 512) return false;
  const row = await db(env).prepare("SELECT resource,expires_at FROM oauth_access WHERE token_hash=?").bind(await hash(raw)).first();
  return !!row && row.resource === expectedResource && row.expires_at >= now();
}

