// functions/oauth/logout.js
import { parseCookies, clearSessionCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const { request, env } = context;
  const noStore = { "Cache-Control": "no-store" };

  // Exige um cabeçalho Origin exatamente igual a PUBLIC_BASE_URL.
  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem não autorizada", { status: 403, headers: noStore });
  }

  const cookies = parseCookies(request);
  const rawSession = cookies["__Host-session"];

  if (rawSession) {
    const sessionHash = await sha256Base64Url(rawSession);
    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(sessionHash).run();
  }

  return new Response(null, {
    status: 204,
    headers: { "Set-Cookie": clearSessionCookie(), ...noStore },
  });
}

// A rota só aceita POST, conforme o contrato do roteiro.
export async function onRequestGet() {
  return new Response("Method not allowed", { status: 405 });
}
