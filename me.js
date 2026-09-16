// functions/api/me.js
import { parseCookies } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const noStore = { "Cache-Control": "no-store" };

  const cookies = parseCookies(request);
  const rawSession = cookies["__Host-session"];
  if (!rawSession) {
    return new Response(null, { status: 401, headers: noStore });
  }

  const sessionHash = await sha256Base64Url(rawSession);
  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB
    .prepare(
      "SELECT issuer, email, display_name, expires_at FROM sessions WHERE id_hash = ?"
    )
    .bind(sessionHash)
    .first();

  if (!row || row.expires_at <= now) {
    return new Response(null, { status: 401, headers: noStore });
  }

  return Response.json(
    {
      issuer: row.issuer,
      email: row.email,
      displayName: row.display_name,
    },
    { headers: noStore }
  );
}
