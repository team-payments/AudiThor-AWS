// /static/js/auth.js  (ESM, sin bundler)

// Cargamos oidc-client-ts desde CDN para que funcione en S3/CloudFront sin build.
const _oidc = import(
  "https://cdn.jsdelivr.net/npm/oidc-client-ts@2.4.1/dist/browser/oidc-client-ts.min.js"
);

// =================== CONFIG COGNITO (AJUSTA ESTO) ===================
// Copia EXACTO el dominio que te muestra Cognito en:
// User pools → App integration → Domain (Hosted UI)
const COGNITO_DOMAIN = "https://us-west-2atd5cvzi3.auth.us-west-2.amazoncognito.com";

// App client ID (el público, sin secret)
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";

// Deben coincidir exactamente con Allowed callback/sign-out URLs en Cognito
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
// ====================================================================

// Preparamos el UserManager una vez cargada la librería
const _userManagerPromise = _oidc.then(({ UserManager, WebStorageStateStore }) => {
  return new UserManager({
    authority: COGNITO_DOMAIN,                 // Hosted UI domain
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
    response_type: "code",                     // Authorization Code Flow (PKCE)
    scope: "openid email profile phone",
    userStore: new WebStorageStateStore({ store: window.localStorage }),
  });
});

// ============== Funciones de ayuda (exportadas) =================
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
  const qs = new URLSearchParams(window.location.search);
  if (qs.has("code") || qs.has("state")) return true;
  const hs = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return hs.has("code") || hs.has("state");
}

export async function completeAuth() {
  const um = await _userManagerPromise;
  await um.signinRedirectCallback();
  // Limpia ?code&state dejando la raíz
  window.history.replaceState({}, document.title, REDIRECT_URI);
}

export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();
    // Evita que el resto del JS siga ejecutándose
    return new Promise(() => {});
  }
  return user;
}

// ============== Auto-inicialización (opcional) =================
// Si quieres forzar login al entrar, deja este bloque activo.
// Si prefieres botón "Login", comenta el IIFE.
(async () => {
  try {
    if (isAuthCallback()) {
      await completeAuth();
    } else {
      // Si no quieres forzar login, comenta la siguiente línea:
      // await requireAuth();
      // O solo actualiza UI de "Not signed in" aquí si lo prefieres.
    }
  } catch (e) {
    console.error("Auth init error:", e);
  }
})();
