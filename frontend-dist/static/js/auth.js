// === auth.js (ESM, sin bundler) ===
// Carga oidc-client-ts desde CDN para que funcione en S3/CloudFront sin build.
const _oidc = import("https://cdn.jsdelivr.net/npm/oidc-client-ts@2.4.1/dist/browser/oidc-client-ts.min.js");

// ⚙️ Configuración Cognito (Hosted UI)
const COGNITO_DOMAIN = "https://audithor-spa-client.auth.us-west-2.amazoncognito.com";
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

// Inicializa UserManager cuando el módulo de OIDC esté cargado
const _userManagerPromise = _oidc.then(({ UserManager, WebStorageStateStore }) => {
  return new UserManager({
    authority: COGNITO_DOMAIN,                     // Hosted UI domain
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
    response_type: "code",                         // Authorization Code Flow
    scope: "openid email profile phone",           // scopes recomendados
    userStore: new WebStorageStateStore({ store: window.localStorage }),
  });
});

// --------------------- Helpers exportados ---------------------
export async function getUser() {
  const um = await _userManagerPromise;
  return um.getUser();
}

export async function login() {
  const um = await _userManagerPromise;
  return um.signinRedirect();
}

export async function logout() {
  const um = await _userManagerPromise;
  return um.signoutRedirect();
}

export function isAuthCallback() {
  // Code Flow: Cognito devuelve ?code=... (&state=...) en la query
  const q = new URLSearchParams(window.location.search);
  if (q.has("code") || q.has("state")) return true;

  // (por si algún proveedor retorna por hash)
  const h = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return h.has("code") || h.has("state");
}

export async function completeAuth() {
  const um = await _userManagerPromise;
  await um.signinRedirectCallback();
  // Limpia parámetros de la URL (quita ?code&state) dejando la raíz
  window.history.replaceState({}, document.title, REDIRECT_URI);
}

export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();
    // Evita que el resto del JS siga ejecutándose en esta carga
    return new Promise(() => {});
  }
  return user;
}

// --------------------- Auto-inicialización opcional ---------------------
// Si quieres que la SPA requiera sesión siempre al entrar, deja este bloque activo.
// Si prefieres controlar tú el flujo (p.ej. botón Login), comenta el IIFE.
(async () => {
  try {
    if (isAuthCallback()) {
      await completeAuth();
    } else {
      await requireAuth();
    }
  } catch (e) {
    console.error("Auth init error:", e);
  }
})();
