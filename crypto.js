// functions/_shared/crypto.js
// Funções utilitárias baseadas apenas em Web Crypto (nenhuma biblioteca externa).

const encoder = new TextEncoder();

// Converte bytes para Base64URL sem preenchimento ("=").
export function toBase64Url(bytes) {
  const view = new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < view.length; i++) bin += String.fromCharCode(view[i]);
  const base64 = btoa(bin);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Converte uma string Base64URL de volta para Uint8Array.
export function fromBase64Url(value) {
  let base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) base64 += "=";
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Gera N bytes aleatórios criptograficamente seguros, codificados em Base64URL.
// Com byteLength = 32, o resultado tem 43 caracteres, como pede o roteiro.
export function randomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

// Calcula o resumo SHA-256 de uma string e devolve em Base64URL.
export async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64Url(digest);
}

// code_challenge (método S256) a partir do code_verifier — RFC 7636.
export async function pkceChallengeFromVerifier(verifier) {
  return sha256Base64Url(verifier);
}
