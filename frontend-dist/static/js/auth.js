// === /static/js/auth.js (ESM, sin bundler, login forzado) ===

// Cargamos oidc-client-ts como ES module real
const OIDC_URL = "https://esm.sh/oidc-client-ts@2.4.1";

// 👉 Dominio del Hosted UI de tu pool (NO el endpoint cognito-idp).
// Lo ves en Cognito → Tu User pool → App integration → Dominio de Cognito
const COGNITO_DOMAIN = "https://us-west-2atd5cvzi3.auth.us-west-2.amazoncognito.com";

// App client (público, sin secret)
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";

// Deben coincidir EXACTAS con Allowed callback URLs / sign-out URLs
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

// ———————————————————————————————————————————————————————————————
//  Carga perezosa de UserManager
// ———————————————————————————————————————————————————————————————
let _userManagerPromise = null;

async function getUserManager() {
  if (_userManagerPromise) return _userManagerPromise;

  _userManagerPromise = (async () => {
    const mod = await import(OIDC_URL);
    const { UserManager, WebStorageStateStore } = mod;

    const settings = {
      authority: COGNITO_DOMAIN,                // Hosted UI domain
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
      response_type: "code",                     // Code flow (PKCE auto)
      scope: "openid email profile phone",
      userStore: new WebStorageStateStore({ store: window.localStorage }),
      automaticSilentRenew: false,               // Hosted UI no iframe silencioso
      clockSkew: 5,
    };

    return new UserManager(settings);
  })();

  return _userManagerPromise;
}

// ———————————————————————————————————————————————————————————————
//  API pública
// ———————————————————————————————————————————————————————————————
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
  // Cognito vuelve con ?code=&state= en la query (o raramente en hash)
  const qs = new URLSearchParams(window.location.search);
  if (qs.has("code") || qs.has("state")) return true;
  const hs = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return hs.has("code") || hs.has("state");
}

export async function completeAuth() {
  const um = await getUserManager();
  await um.signinRedirectCallback();
  // Limpia ?code&state de la barra
  window.history.replaceState({}, document.title, REDIRECT_URI);
}

export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();              // redirige al Hosted UI
    return new Promise(() => {}); // corta la ejecución en esta carga
  }
  return user;
}

// ———————————————————————————————————————————————————————————————
//  Auto-init: fuerza login SIEMPRE antes de mostrar la app
//  (deja este bloque tal cual para “no ver nada” hasta iniciar sesión)
// ———————————————————————————————————————————————————————————————
(async () => {
  try {
    if (isAuthCallback()) {
      await completeAuth();     // procesa el retorno de Cognito
    } else {
      await requireAuth();      // si no hay sesión, redirige a login
    }
  } catch (err) {
    // Si hay un fallo de red puntual en la discovery, verás aquí el error.
    // El usuario puede recargar; el flujo no expone la app sin sesión.
    console.error("Auth init error:", err);
  }
})();
