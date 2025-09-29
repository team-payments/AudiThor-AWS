// === /static/js/auth.js (ESM, sin bundler) ===
// Cargamos oidc-client-ts como ES module real (evita "no es un constructor").
const OIDC_URL = "https://esm.sh/oidc-client-ts@2.4.1";

// 👉 DOMINIO DEL HOSTED UI (NO el endpoint cognito-idp)
const COGNITO_DOMAIN = "https://us-west-2atd5cvzi3.auth.us-west-2.amazoncognito.com";

// App client (público, sin secret)
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";

// Deben coincidir EXACTAS con Allowed callback URLs y Allowed sign-out URLs
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

/* ------------------------------------------------------------------ */
/*   Carga del módulo y creación perezosa del UserManager              */
/* ------------------------------------------------------------------ */
let _userManagerPromise = null;

async function importOidc() {
  // 1) Intento principal: esm.sh (ESM real)
  try {
    const mod = await import(OIDC_URL);
    if (mod?.UserManager && mod?.WebStorageStateStore) return mod;
  } catch (e) {
    console.warn("No se pudo cargar oidc-client-ts desde esm.sh:", e);
  }

  // 2) Fallback opcional: jsDelivr ESM build (por si el anterior falla)
  try {
    const alt = await import(
      "https://cdn.jsdelivr.net/npm/oidc-client-ts@2.4.1/dist/browser/oidc-client-ts.min.js"
    );
    // Algunos builds exponen en default; normalizamos
    const mod = alt?.default ? alt.default : alt;
    if (mod?.UserManager && mod?.WebStorageStateStore) return mod;
  } catch (e) {
    console.warn("Fallback jsDelivr también falló:", e);
  }

  throw new Error("No se pudo cargar oidc-client-ts desde los CDNs.");
}

async function getUserManager() {
  if (_userManagerPromise) return _userManagerPromise;

  _userManagerPromise = (async () => {
    const { UserManager, WebStorageStateStore } = await importOidc();

    const settings = {
      // 👇 MUY IMPORTANTE: el dominio del Hosted UI
      authority: COGNITO_DOMAIN,

      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,

      response_type: "code",                // Authorization Code + PKCE (auto)
      scope: "openid email profile phone",

      // Persistimos sesión OIDC en localStorage
      userStore: new WebStorageStateStore({ store: window.localStorage }),

      // Ajustes seguros para SPA con Hosted UI
      automaticSilentRenew: false,          // Hosted UI no soporta silent iframe
      clockSkew: 5,                          // tolerancia de reloj (segundos)
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
