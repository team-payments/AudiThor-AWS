<!-- static/js/auth.js (ESM, sin bundler) -->
<script type="module">
// Carga oidc-client-ts desde CDN para funcionar en S3/CloudFront
const _oidc = import("https://cdn.jsdelivr.net/npm/oidc-client-ts@2.4.1/dist/browser/oidc-client-ts.min.js");

// ⚙️ Config Cognito (Hosted UI) — USA SIEMPRE TU SUBDOMINIO DEL HOSTED UI
const HOSTED_UI_DOMAIN = "https://audithor-spa-client.auth.us-west-2.amazoncognito.com";
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";

// Construye la URL DE DISCOVERY correcta del Hosted UI (no la del pool)
const OIDC_METADATA_URL = `${HOSTED_UI_DOMAIN}/.well-known/openid-configuration`;

const _userManagerPromise = _oidc.then(({ UserManager, WebStorageStateStore }) => {
  console.log("[Auth] Using authority:", HOSTED_UI_DOMAIN);
  console.log("[Auth] Using metadataUrl:", OIDC_METADATA_URL);

  return new UserManager({
    // Fuerza el Hosted UI como autoridad
    authority: HOSTED_UI_DOMAIN,

    // Y fuerza el documento de discovery para evitar que lo sobreescriba otra cosa
    metadataUrl: OIDC_METADATA_URL,

    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,

    response_type: "code",
    scope: "openid email profile phone",

    // Persistencia en localStorage
    userStore: new WebStorageStateStore({ store: window.localStorage }),

    // Opcional: desactiva silenciosos si no los usas
    automaticSilentRenew: false,
    monitorSession: false,
  });
});

// ------------- Helpers -------------
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
  const q = new URLSearchParams(window.location.search);
  if (q.has("code") || q.has("state")) return true;
  const h = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  return h.has("code") || h.has("state");
}

export async function completeAuth() {
  const um = await _userManagerPromise;
  await um.signinRedirectCallback();
  // Limpia ?code&state
  window.history.replaceState({}, document.title, REDIRECT_URI);
}

export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();
    return new Promise(() => {}); // corta ejecución
  }
  return user;
}

// ------------- Auto-init (opcional) -------------
(async () => {
  try {
    if (isAuthCallback()) {
      await completeAuth();
    } else {
      // Si prefieres que sólo haga login al pulsar un botón, comenta esta línea
      // await requireAuth();

      // En su lugar, muestra el botón "Login" y que llame a login()
      console.log("[Auth] Not signed in");
    }
  } catch (e) {
    console.error("Auth init error:", e);
  }
})();
</script>
