// functions/_shared/oidc.js
// Confirmação de identidade dos dois provedores, usando apenas Web Crypto e fetch.

import { fromBase64Url } from "./crypto.js";

const textDecoder = new TextDecoder();

function base64UrlToJson(segment) {
  const bytes = fromBase64Url(segment);
  return JSON.parse(textDecoder.decode(bytes));
}

// Valida a assinatura (RS256) e as claims do id_token do Google, sem libs externas.
export async function verifyGoogleIdToken(
  idToken,
  { clientId, issuer, discoveryUrl, expectedNonce }
) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("formato de id_token inválido");
  const [headerSeg, payloadSeg, signatureSeg] = parts;

  const header = base64UrlToJson(headerSeg);
  if (header.alg !== "RS256") throw new Error("algoritmo inesperado");

  const payload = base64UrlToJson(payloadSeg);

  const discoveryResponse = await fetch(discoveryUrl);
  if (!discoveryResponse.ok) throw new Error("falha ao obter documento de descoberta");
  const discovery = await discoveryResponse.json();

  const jwksResponse = await fetch(discovery.jwks_uri);
  if (!jwksResponse.ok) throw new Error("falha ao obter JWKS");
  const jwks = await jwksResponse.json();

  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("chave pública não encontrada para o kid recebido");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
  const signature = fromBase64Url(signatureSeg);
  const validSignature = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signedData
  );
  if (!validSignature) throw new Error("assinatura inválida");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer && payload.iss !== discovery.issuer) {
    throw new Error("emissor inválido");
  }
  if (payload.aud !== clientId) throw new Error("audiência inválida");
  if (typeof payload.exp !== "number" || payload.exp <= now) throw new Error("token expirado");
  if (typeof payload.iat !== "number" || payload.iat > now + 60) throw new Error("iat inválido");
  if (payload.nonce !== expectedNonce) throw new Error("nonce inválido");

  return payload;
}

// Consulta o perfil autenticado no GitHub com o access_token recebido.
export async function fetchGithubUser(accessToken) {
  const response = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "oauth-pages-lab",
    },
  });
  if (!response.ok) throw new Error("falha ao consultar /user");
  const profile = await response.json();
  if (typeof profile.id !== "number") throw new Error("perfil sem id numérico");
  return profile;
}

// Revoga a autorização concedida à OAuth App (elimina access_token e refresh_token).
export async function revokeGithubGrant(accessToken, clientId, clientSecret) {
  const basicAuth = btoa(`${clientId}:${clientSecret}`);
  const response = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
    method: "DELETE",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "Content-Type": "application/json",
      "User-Agent": "oauth-pages-lab",
    },
    body: JSON.stringify({ access_token: accessToken }),
  });
  if (response.status !== 204) throw new Error("falha ao revogar a autorização do GitHub");
}
