// === /static/js/auth.js (ESM, sin bundler, login forzado, sin CORS issues) ===

// Cargamos oidc-client-ts como ES module real
const OIDC_URL = "https://esm.sh/oidc-client-ts@2.4.1";

// ⚙️ Configuración Cognito
// 1) Dominio del Hosted UI que ya tienes activo
const COGNITO_DOMAIN = "https://us-west-23zjobwexd.auth.us-west-2.amazoncognito.com";

// 2) Issuer del User Pool (Cognito IdP) → lo ves en: Descripción general del pool
const REGION = "us-west-2";
const USER_POOL_ID = "us-west-2_3ZjOBWEXD"; // <-- confirma que está exactamente así

// 3) App client (público, sin secret)
const CLIENT_ID = "5na4dcm4dond1uo5emfk9platr";

// 4) Deben coincidir EXACTAS con Allowed callback URLs / sign-out URLs
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

// 5) Authority con CORS (issuer del pool)
const AUTHORITY = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;

// 6) Metadata OIDC fija apuntando al Hosted UI para evitar discovery contra el Hosted UI
const OIDC_METADATA = {
  issuer: AUTHORITY,
  authorization_endpoint: `${COGNITO_DOMAIN}/oauth2/authorize`,
  token_endpoint:         `${COGNITO_DOMAIN}/oauth2/token`,
  end_session_endpoint:   `${COGNITO_DOMAIN}/logout`,
  userinfo_endpoint:      `${COGNITO_DOMAIN}/oauth2/userInfo`,
  jwks_uri:               `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}/.well-known/jwks.json`,
};

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
      authority: AUTHORITY,
      metadata: OIDC_METADATA,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
      response_type: "code",
      scope: "openid email profile",

      // 👇 Usa el mismo almacén para estado y usuario
      userStore:  new WebStorageStateStore({ store: window.localStorage }),
      stateStore: new WebStorageStateStore({ store: window.localStorage }),

      automaticSilentRenew: false,
      clockSkew: 5,
    };
    return new UserManager(settings);
  })();

  return _userManagerPromise;
}

// ———————————————————————————————————————————————————————————————
//  Helpers
// ———————————————————————————————————————————————————————————————
function isAuthCallback() {
  const qs = new URLSearchParams(window.location.search);
  if (qs.has("code") || qs.has("state")) return true;
  const hs = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return hs.has("code") || hs.has("state");
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
  // Limpia cualquier rastro local antes de salir
  try {
    const um = await getUserManager();
    await um.removeUser(); // borra el user de oidc-client-ts
  } catch {}
  try { localStorage.clear(); sessionStorage.clear(); } catch {}

  // Queremos volver a la app y relanzar login automáticamente
  const returnTo = `${REDIRECT_URI}?logged_out=1`;

  // Redirección manual al Hosted UI de Cognito (forma soportada por Cognito)
  const url =
    `${COGNITO_DOMAIN}/logout` +
    `?client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&logout_uri=${encodeURIComponent(returnTo)}`;

  window.location.href = url;
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
//  + relanza login si venimos de logout (?logged_out=1)
// ———————————————————————————————————————————————————————————————
(async () => {
  try {
    const qs = new URLSearchParams(window.location.search);
    if (qs.get("logged_out") === "1") {
      // limpiamos el flag para evitar bucles
      window.history.replaceState({}, document.title, REDIRECT_URI);
      await login(); // abrir Hosted UI de Cognito
      return;
    }

    if (isAuthCallback()) {
      await completeAuth();     // procesa el retorno de Cognito
    } else {
      await requireAuth();      // si no hay sesión, redirige a login
    }
  } catch (err) {
    console.error("Auth init error:", err);
  }
})();

// Cambios de sesión (para refrescar UI externa)
export async function onAuthChange(cb) {
  const um = await getUserManager();
  um.events.addUserLoaded(cb);         // cuando hay login o refresh
  um.events.addUserUnloaded(cb);       // cuando se borra el user
  um.events.addAccessTokenExpired(cb); // cuando expira el token
  um.events.addUserSignedOut(cb);      // cuando hace logout
}
