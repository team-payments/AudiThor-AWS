// === /static/js/auth.js (ESM, sin bundler) ===
// Cargamos oidc-client-ts como ES module real (evita "no es un constructor").
const OIDC_URL = "https://esm.sh/oidc-client-ts@2.4.1";

// 👉 PON AQUÍ TU DOMINIO DEL HOSTED UI (no el endpoint cognito-idp):
// Formato: https://<pool-prefix>.auth.<region>.amazoncognito.com
const COGNITO_DOMAIN = "https://us-west-2atd5cvzi3.auth.us-west-2.amazoncognito.com";

// App client (público, sin secret)
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";

// Deben coincidir EXACTAS con lo configurado en “Allowed callback URLs” y “Allowed sign-out URLs”
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

/* ------------------------------------------------------------------ */
/*   Carga del módulo y creación perezosa del UserManager              */
/* ------------------------------------------------------------------ */
let _userManagerPromise = null;

async function getUserManager() {
  if (_userManagerPromise) return _userManagerPromise;

  _userManagerPromise = (async () => {
    // Cargamos el bundle ESM
    const mod = await import(OIDC_URL);
    // oidc-client-ts exporta las clases como export nombrado
    const { UserManager, WebStorageStateStore } = mod;

    // Config OIDC apuntando al Hosted UI (authority)
    const settings = {
      authority: COGNITO_DOMAIN,                    // 👈 Hosted UI domain
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
      response_type: "code",                        // Code flow (PKCE auto)
      scope: "openid email profile phone",
      // Persistimos sesión OIDC en localStorage
      userStore: new WebStorageStateStore({ store: window.localStorage }),

      // Opcional: tiempos de tolerancia de reloj para evitar desajustes
      clockSkew: 5,
      automaticSilentRenew: false,                  // (Hosted UI no permite silent iframe)
    };

    return new UserManager(settings);
  })();

  return _userManagerPromise;
}

/* ------------------------------------------------------------------ */
/*   Helpers públicos                                                  */
/* ------------------------------------------------------------------ */
export async function getUser() {
  const um = await getUserManager();
  return um.getUser();
}

export async function login() {
  const um = await getUserManager();
  return um.signinRedirect();
}

export async function logout() {
  const um = await getUserManager();
  return um.signoutRedirect();
}

export function isAuthCallback() {
  // Code Flow: Cognito vuelve con ?code y ?state
  const qs = new URLSearchParams(window.location.search);
  if (qs.has("code") || qs.has("state")) return true;

  // Por si algún proveedor devolviera por hash
  const hs = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return hs.has("code") || hs.has("state");
}

export async function completeAuth() {
  const um = await getUserManager();
  await um.signinRedirectCallback();
  // Limpiamos la query para no dejar ?code&state en la barra
  window.history.replaceState({}, document.title, REDIRECT_URI);
}

export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();
    // Evitar seguir ejecutando el resto del JS tras redirigir
    return new Promise(() => {});
  }
  return user;
}

/* ------------------------------------------------------------------ */
/*   Auto-init opcional: fuerza sesión al entrar                       */
/*   Si prefieres controlar con botón "Login", comenta este bloque.    */
/* ------------------------------------------------------------------ */
(async () => {
  try {
    if (isAuthCallback()) {
      await completeAuth();
    } else {
      // Si no quieres forzar login, comenta esta línea:
      await requireAuth();
    }
  } catch (err) {
    console.error("Auth init error:", err);
  }
})();
