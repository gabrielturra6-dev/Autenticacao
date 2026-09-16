# oauth-pages-lab

Implementação completa do laboratório "login em um site estático no Cloudflare
Pages": página pública + Pages Functions para login com Google e GitHub,
sessão opaca em D1.

## O que já está pronto neste projeto

- `public/` — página estática (`index.html`, `app.js`, `styles.css`).
- `functions/_shared/` — utilitários reaproveitados pelas rotas:
  - `crypto.js`: tokens aleatórios, SHA-256, code_challenge PKCE.
  - `cookies.js`: leitura e montagem dos cookies `__Host-oauth-tx` e `__Host-session`.
  - `providers.js`: endpoints e configuração de Google e GitHub.
  - `oidc.js`: validação do `id_token` do Google (JWKS + RS256, sem libs) e
    integração com a API do GitHub (`/user` + revogação do grant).
- `functions/api/health.js` e `functions/api/me.js`.
- `functions/oauth/login/[provider].js`, `functions/oauth/callback/[provider].js`,
  `functions/oauth/logout.js`.
- `schema.sql` — esquema das tabelas `oauth_transactions` e `sessions`.

Nenhum arquivo usa `package.json`, npm ou Wrangler: é só JavaScript com as
Web APIs que o runtime do Cloudflare já oferece.

## Passo a passo para colocar no ar

Siga exatamente a ordem do roteiro da disciplina (seções 7 a 15). Resumo:

1. **Suba este código para um repositório novo no GitHub**, com `public/` e
   `functions/` como pastas irmãs na raiz.
2. **Cloudflare Pages → Create application → Pages → Connect to Git.**
   - Framework preset: `None`
   - Build command: (vazio)
   - Build output directory: `public`
   - Ramificação de produção: `main`
3. **Confirme `/api/health`** na URL `.pages.dev` gerada — deve responder 200.
4. **Crie o banco D1** (`Storage & Databases → D1 SQL Database`), rode o
   conteúdo de `schema.sql` no console, e depois **ligue o banco ao projeto**
   em `Settings → Bindings`, com o nome exato `DB`.
5. **Registre o cliente Web no Google Cloud** com a URL de retorno
   `https://SEU-PROJETO.pages.dev/oauth/callback/google` (escopos: `openid email profile`).
6. **Registre a OAuth App no GitHub** com Homepage URL = `https://SEU-PROJETO.pages.dev`
   e Authorization callback URL = `https://SEU-PROJETO.pages.dev/oauth/callback/github`.
7. **Cadastre as variáveis e segredos no Pages** (`Settings → Variables and Secrets`):
   - texto simples: `PUBLIC_BASE_URL`, `GOOGLE_CLIENT_ID`, `GITHUB_CLIENT_ID`
   - criptografados: `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_SECRET`
8. **Reimplante** o projeto depois de qualquer mudança de binding/variável —
   elas só valem a partir da implantação seguinte.
9. Teste o caminho feliz e os seis casos de falha da seção 16 do roteiro.

## Onde cada requisito do contrato foi atendido

- PKCE S256 obrigatório nos dois provedores: gerado em `login/[provider].js`,
  conferido implicitamente pelo próprio provedor na troca de tokens.
- `state` e transação de uso único: gravados como resumo SHA-256 no D1 e
  apagados **antes** da troca de tokens, em `callback/[provider].js`.
- `nonce` só existe no fluxo do Google (OIDC) e é validado em `oidc.js`.
- O `id_token` do Google é verificado manualmente (JWKS + RSASSA-PKCS1-v1_5),
  sem nenhuma biblioteca de terceiros.
- O `access_token` do GitHub só é usado para `GET /user` e é revogado com
  `DELETE /applications/{client_id}/grant` antes de a sessão ser criada.
- O cookie de sessão é opaco: o D1 só guarda o hash SHA-256 do valor bruto.
- `/api/me` e `/oauth/logout` sempre respondem com `Cache-Control: no-store`.
- `/oauth/logout` exige `Origin` igual a `PUBLIC_BASE_URL` antes de revogar.
