// === auth.js (ESM sin bundler; carga UMD de oidc-client-ts) ===

// Carga el bundle UMD que expone window.oidc (UserManager, etc.)
const _oidc = new Promise((resolve, reject) => {
  if (window.oidc) return resolve(window.oidc); // ya cargado
  const s = document.createElement("script");
  s.src =
    "https://cdn.jsdelivr.net/npm/oidc-client-ts@2.4.1/dist/browser/oidc-client-ts.min.js";
  s.async = true;
  s.onload = () => {
    if (window.oidc) resolve(window.oidc);
    else reject(new Error("oidc-client-ts UMD not available on window.oidc"));
  };
  s.onerror = () => reject(new Error("Failed to load oidc-client-ts script"));
  document.head.appendChild(s);
});

// ⚙️ Configuración Cognito (Hosted UI)
const COGNITO_DOMAIN =
  "https://audithor-spa-client.auth.us-west-2.amazoncognito.com"; // sin /login
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

// Inicializa UserManager cuando el bundle esté cargado
const _userManagerPromise = _oidc.then(({ UserManager }) => {
  return new UserManager({
    authority: COGNITO_DOMAIN,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
    response_type: "code", // Authorization Code + PKCE
    scope: "openid email profile phone",
    // oidc-client-ts ya persiste en storage apropiado por defecto
    // (opcional) loadUserInfo: true,
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

  // Por si algún IdP devuelve en hash
  const h = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return h.has("code") || h.has("state");
}

export async function completeAuth() {
  const um = await _userManagerPromise;
  await um.signinRedirectCallback();
  // Limpia parámetros (?code&state) dejando la raíz exacta
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

// --------------------- Auto-inicialización ---------------------
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
