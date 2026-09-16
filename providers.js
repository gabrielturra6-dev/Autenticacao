// functions/_shared/providers.js
// Configuração dos dois provedores suportados. Nenhum segredo fica fixo no
// código: tudo vem de context.env, cadastrado no painel do Cloudflare Pages.

export function getProviderConfig(provider, env) {
  if (provider === "google") {
    return {
      name: "google",
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      issuer: "https://accounts.google.com",
      discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      scope: "openid email profile",
      usesNonce: true,
    };
  }
  if (provider === "github") {
    return {
      name: "github",
      authorizationEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      usesNonce: false,
    };
  }
  return null;
}

// Monta a URL de retorno exata cadastrada no provedor.
export function redirectUriFor(provider, env) {
  return `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
}
