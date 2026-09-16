// functions/oauth/callback/[provider].js
import {
  parseCookies,
  buildSessionCookie,
  clearTransactionCookie,
} from "../../_shared/cookies.js";
import { randomToken, sha256Base64Url } from "../../_shared/crypto.js";
import { getProviderConfig, redirectUriFor } from "../../_shared/providers.js";
import {
  verifyGoogleIdToken,
  fetchGithubUser,
  revokeGithubGrant,
} from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const { request, params, env } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  // 1) recusa error ou ausência de code/state.
  if (error || !code || !state) {
    return new Response("Requisição inválida", {
      status: 400,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // 2) exige o cookie temporário.
  const cookies = parseCookies(request);
  const rawTxId = cookies["__Host-oauth-tx"];
  if (!rawTxId) {
    return new Response("Transação ausente", {
      status: 400,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // 3) localiza a transação não expirada pelo resumo do cookie.
  const idHash = await sha256Base64Url(rawTxId);
  const now = Math.floor(Date.now() / 1000);

  const tx = await env.DB.prepare(
    "SELECT provider, state_hash, nonce, code_verifier, expires_at FROM oauth_transactions WHERE id_hash = ?"
  )
    .bind(idHash)
    .first();

  if (!tx || tx.provider !== provider || tx.expires_at <= now) {
    return new Response("Transação inválida ou expirada", {
      status: 400,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // 4) compara o resumo de state.
  const stateHash = await sha256Base64Url(state);
  if (stateHash !== tx.state_hash) {
    return new Response("State inválido", {
      status: 400,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // 5) apaga a transação antes de concluir (uso único).
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?")
    .bind(idHash)
    .run();

  const config = getProviderConfig(provider, env);
  const redirectUri = redirectUriFor(provider, env);

  // 6) troca o código com o code_verifier e o Client Secret do provedor correto.
  const tokenBody = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: tx.code_verifier,
  });

  const tokenResponse = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: tokenBody.toString(),
  });

  if (!tokenResponse.ok) {
    return new Response("Falha na troca de tokens", {
      status: 400,
      headers: { "Cache-Control": "no-store" },
    });
  }
  const tokenData = await tokenResponse.json();

  // 7) valida a resposta de identidade conforme o contrato do provedor.
  let issuer, subject, email, displayName;

  try {
    if (provider === "google") {
      if (!tokenData.id_token) throw new Error("resposta sem id_token");
      const claims = await verifyGoogleIdToken(tokenData.id_token, {
        clientId: config.clientId,
        issuer: config.issuer,
        discoveryUrl: config.discoveryUrl,
        expectedNonce: tx.nonce,
      });
      issuer = config.issuer;
      subject = claims.sub;
      email = claims.email ?? null;
      displayName = claims.name ?? null;
    } else {
      if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type || "")) {
        throw new Error("resposta de token inválida");
      }
      const profile = await fetchGithubUser(tokenData.access_token);
      // Revoga a autorização (e todos os tokens associados) antes de criar a sessão.
      await revokeGithubGrant(tokenData.access_token, config.clientId, config.clientSecret);
      issuer = "https://github.com";
      subject = String(profile.id);
      email = profile.email ?? null;
      displayName = profile.name ?? profile.login ?? null;
    }
  } catch (err) {
    return new Response("Falha ao confirmar a identidade", {
      status: 400,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // 8) cria uma sessão opaca (o D1 guarda apenas o resumo do cookie).
  const rawSessionId = randomToken(32);
  const sessionHash = await sha256Base64Url(rawSessionId);
  const sessionExpiresAt = now + 28800;

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sessionHash, issuer, subject, email, displayName, sessionExpiresAt, now)
    .run();

  // 9) limpa o cookie temporário e 10) redireciona para PUBLIC_BASE_URL.
  const headers = new Headers();
  headers.append("Set-Cookie", clearTransactionCookie());
  headers.append("Set-Cookie", buildSessionCookie(rawSessionId));
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
