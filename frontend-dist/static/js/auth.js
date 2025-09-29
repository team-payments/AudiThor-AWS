// === auth.js ===
import { UserManager, WebStorageStateStore } from "oidc-client-ts";

// ⚠️ Rellena con tus datos reales
const COGNITO_DOMAIN = "https://<tu-dominio>.auth.us-west-2.amazoncognito.com"; 
// Ej: https://audithor-spa-client.auth.us-west-2.amazoncognito.com
const CLIENT_ID = "<tu-app-client-id>"; // sin secret
const REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/";      // EXACTA
const POST_LOGOUT_REDIRECT_URI = "https://d38k4y82pqltc.cloudfront.net/"; // EXACTA

const cognitoAuthConfig = {
  // Recomendado: usar el dominio de Hosted UI como authority
  authority: COGNITO_DOMAIN,
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  post_logout_redirect_uri: POST_LOGOUT_REDIRECT_URI,
  response_type: "code",
  scope: "openid email phone",
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  // Descubrimiento OIDC: el dominio Hosted UI publica /.well-known/openid-configuration
};

export const userManager = new UserManager(cognitoAuthConfig);

export function isAuthCallback() {
  // Code Flow: Cognito devuelve ?code=... (&state=...)
  const q = new URLSearchParams(window.location.search);
  return q.has("code") || q.has("state");
}

export async function completeAuth() {
  await userManager.signinRedirectCallback();
  // Limpia la query para no dejar el ?code en la barra
  const url = new URL(window.location.href);
  url.search = "";
  window.history.replaceState({}, "", url.toString());
}

export function login() {
  return userManager.signinRedirect();
}

export function logout() {
  return userManager.signoutRedirect();
}

export function getUser() {
  return userManager.getUser();
}

/** Fuerza login si no hay sesión */
export async function requireAuth() {
  const user = await getUser();
  if (!user || user.expired) {
    await login();
    return new Promise(() => {}); // evitar continuar ejecutando el resto de JS
  }
  return user;
}

// Inicialización automática
(async () => {
  if (isAuthCallback()) {
    await completeAuth();
  } else {
    await requireAuth();
  }
})();
