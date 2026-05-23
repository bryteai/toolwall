/**
 * Minimal OAuth 2.1 PKCE handlers for an MCP server.
 *
 * What's here:
 *   - /.well-known/oauth-authorization-server   — RFC 8414 metadata
 *   - /authorize                                — code+PKCE flow start
 *   - /token                                    — code → access token exchange
 *
 * What's NOT here:
 *   - A real identity provider. This template issues opaque tokens
 *     keyed by KV; a production deployment swaps `verifyUser` with
 *     an upstream IdP (GitHub OAuth App, WorkOS, Auth0, etc.).
 *
 * The MCP spec section 2.5 (Streamable HTTP authorization) requires
 * the resource server to advertise `oauth-authorization-server` and
 * to reject tokens that don't bind to the registered audience.
 */

export interface OAuthEnv {
  readonly OAUTH: KVNamespace;
  readonly OAUTH_ISSUER: string;
  readonly OAUTH_CLIENT_ID: string;
  readonly OAUTH_CLIENT_SECRET: string;
}

const TOKEN_TTL_SECONDS = 60 * 60;
const CODE_TTL_SECONDS = 60 * 5;

interface PendingCode {
  readonly clientId: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly redirectUri: string;
  readonly scope: string;
  readonly subject: string;
}

export function metadata(env: OAuthEnv): Response {
  const body = {
    issuer: env.OAUTH_ISSUER,
    authorization_endpoint: `${env.OAUTH_ISSUER}/authorize`,
    token_endpoint: `${env.OAUTH_ISSUER}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    scopes_supported: ["mcp:invoke"],
  };
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
  });
}

export async function authorize(
  req: Request,
  env: OAuthEnv,
): Promise<Response> {
  const u = new URL(req.url);
  const clientId = u.searchParams.get("client_id");
  const codeChallenge = u.searchParams.get("code_challenge");
  const codeChallengeMethod = u.searchParams.get("code_challenge_method");
  const redirectUri = u.searchParams.get("redirect_uri");
  const scope = u.searchParams.get("scope") ?? "mcp:invoke";
  const state = u.searchParams.get("state") ?? "";

  if (
    !clientId ||
    clientId !== env.OAUTH_CLIENT_ID ||
    !codeChallenge ||
    codeChallengeMethod !== "S256" ||
    !redirectUri
  ) {
    return new Response("invalid_request", { status: 400 });
  }

  // PRODUCTION: bounce the user to your real IdP and round-trip back.
  // For the scaffold we trust the call.
  const subject = u.searchParams.get("login_hint") ?? "anonymous";

  const code = crypto.randomUUID().replaceAll("-", "");
  const pending: PendingCode = {
    clientId,
    codeChallenge,
    codeChallengeMethod: "S256",
    redirectUri,
    scope,
    subject,
  };
  await env.OAUTH.put(`code:${code}`, JSON.stringify(pending), {
    expirationTtl: CODE_TTL_SECONDS,
  });

  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  return Response.redirect(redirect.toString(), 302);
}

export async function token(req: Request, env: OAuthEnv): Promise<Response> {
  const form = await req.formData();
  const grantType = form.get("grant_type");
  const code = form.get("code");
  const redirectUri = form.get("redirect_uri");
  const clientId = form.get("client_id");
  const clientSecret = form.get("client_secret");
  const codeVerifier = form.get("code_verifier");

  if (
    grantType !== "authorization_code" ||
    typeof code !== "string" ||
    typeof codeVerifier !== "string" ||
    typeof redirectUri !== "string" ||
    clientId !== env.OAUTH_CLIENT_ID ||
    clientSecret !== env.OAUTH_CLIENT_SECRET
  ) {
    return jsonError("invalid_request", 400);
  }

  const pendingRaw = await env.OAUTH.get(`code:${code}`);
  if (!pendingRaw) return jsonError("invalid_grant", 400);
  const pending = JSON.parse(pendingRaw) as PendingCode;
  await env.OAUTH.delete(`code:${code}`);

  if (pending.redirectUri !== redirectUri) {
    return jsonError("invalid_grant", 400);
  }

  const computed = await s256(codeVerifier);
  if (computed !== pending.codeChallenge) {
    return jsonError("invalid_grant", 400);
  }

  const accessToken = `tw_${crypto.randomUUID().replaceAll("-", "")}`;
  await env.OAUTH.put(
    `tok:${accessToken}`,
    JSON.stringify({ sub: pending.subject, scope: pending.scope }),
    { expirationTtl: TOKEN_TTL_SECONDS },
  );

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL_SECONDS,
      scope: pending.scope,
    }),
    { headers: { "content-type": "application/json" } },
  );
}

export async function verifyBearer(
  req: Request,
  env: OAuthEnv,
): Promise<{ sub: string; scope: string } | null> {
  const auth = req.headers.get("authorization") ?? "";
  const m = /^Bearer (.+)$/.exec(auth);
  if (!m || !m[1]) return null;
  const raw = await env.OAUTH.get(`tok:${m[1]}`);
  if (!raw) return null;
  return JSON.parse(raw) as { sub: string; scope: string };
}

async function s256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return b64url(new Uint8Array(digest));
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function jsonError(error: string, status: number): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "content-type": "application/json" },
  });
}
