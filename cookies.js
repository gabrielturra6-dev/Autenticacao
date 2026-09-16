// functions/_shared/cookies.js

// Lê o cabeçalho Cookie da requisição e devolve um objeto { nome: valor }.
export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  header.split(";").forEach((part) => {
    const eq = part.indexOf("=");
    if (eq === -1) return;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) cookies[name] = value;
  });
  return cookies;
}

// Cookie temporário de transação (10 minutos), conforme o contrato do roteiro.
export function buildTransactionCookie(value) {
  return `__Host-oauth-tx=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

export function clearTransactionCookie() {
  return `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// Cookie de sessão (8 horas), opaco e com SameSite=Strict.
export function buildSessionCookie(value) {
  return `__Host-session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

export function clearSessionCookie() {
  return `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
