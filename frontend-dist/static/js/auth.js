// /static/js/auth.js  (ESM, sin bundler; robusto para CDN)

const _lib = import(
  "https://cdn.jsdelivr.net/npm/oidc-client-ts@2.4.1/dist/browser/oidc-client-ts.min.js"
);

// ====== AJUSTA ESTOS VALORES ======
const COGNITO_DOMAIN = "https://<TU-PREFIX>.auth.us-west-2.amazoncognito.com";
const CLIENT_ID = "2faon57u5n65mliv7ncj1us53";
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";
// ==================================

// Normaliza exportaciones del bundle del navegador (default / global window.oidc)
async function getOidc() {
  try {
    const m = await _lib;
    const maybe = m?.default ?? m;
    if (maybe?.UserManager && maybe?.WebStorageStateStore) return maybe;
  } catch {}
  const g = (window.oidc || window.Oidc || {});
  if (g?.UserManager && g?.WebStorageStateStore) return g;
  throw new Error("No se pudo cargar oidc-client-ts desde el CDN.");
}

const _userManagerPromise = (async () => {
  const { UserManager, WebStorageStateStore } = await getOidc();
  return new UserManager({
    authority: COGNITO_DOMAIN,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile phone",
    userStore: new WebStorageStateStore({ store: window.localStorage }),
  });
})();

// ---------------- API ----------------
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
  window.history.replaceState({}, document.title, REDIRECT_URI);
}

export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();
    return new Promise(() => {});
  }
  return user;
}

// --------- Auto-init opcional ---------
// Si no quieres forzar login automático, deja SOLO el callback.
(async () => {
  try {
    if (isAuthCallback()) {
      await completeAuth();
    }
    // Si prefieres forzar sesión al entrar, descomenta:
    // else { await requireAuth(); }
  } catch (e) {
    console.error("Auth init error:", e);
  }
})();

// Botón “Login”/“Logout” opcional si existen en el DOM
document.addEventListener("DOMContentLoaded", async () => {
  const loginBtn = document.querySelector("#loginBtn, .login-btn, #auth-btn");
  if (loginBtn) loginBtn.addEventListener("click", () => login());

  const logoutBtn = document.querySelector("#logoutBtn, .logout-btn");
  if (logoutBtn) logoutBtn.addEventListener("click", () => logout());

  // Muestra estado mínimo si tienes un placeholder en el sidebar
  const statusEl = document.querySelector("#user-email, #user-status, #userbar-email");
  try {
    const user = await getUser();
    if (user && !user.expired && statusEl) {
      statusEl.textContent = user?.profile?.email || "Signed in";
    }
  } catch {}
});
