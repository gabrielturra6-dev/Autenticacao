// functions/oauth/login/[provider].js
import {
  randomToken,
  sha256Base64Url,
  pkceChallengeFromVerifier,
} from "../../_shared/crypto.js";
import { buildTransactionCookie } from "../../_shared/cookies.js";
import { getProviderConfig, redirectUriFor } from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const { params, env } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  const config = getProviderConfig(provider, env);

  // Valores da transação: identificador do cookie, state, nonce e code_verifier.
  const rawTxId = randomToken(32);
  const state = randomToken(32);
  const codeVerifier = randomToken(32);
  const nonce = provider === "google" ? randomToken(32) : null;
  const codeChallenge = await pkceChallengeFromVerifier(codeVerifier);

  const idHash = await sha256Base64Url(rawTxId);
  const stateHash = await sha256Base64Url(state);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  // O D1 guarda apenas resumos (id_hash, state_hash), nunca o valor bruto do cookie.
  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.set("client_id", config.clientId);
  authUrl.searchParams.set("redirect_uri", redirectUriFor(provider, env));
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", config.scope);
    authUrl.searchParams.set("nonce", nonce);
  }
  // Para o GitHub, scope e nonce são deliberadamente omitidos.

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": buildTransactionCookie(rawTxId),
      "Cache-Control": "no-store",
    },
  });
}
