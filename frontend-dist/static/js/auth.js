// /static/js/auth.js
import { UserManager } from "https://cdn.jsdelivr.net/npm/oidc-client-ts@2.2.1/+esm";

// Rellena con tus valores reales de Cognito
const cognitoAuthConfig = {
  authority: "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ATD5cVZi3", // User Pool issuer
  client_id: "2faon57u5n65mliv7ncj1us53", // App client ID
  redirect_uri: "https://d38k4y82pqltc.cloudfront.net", // URL pública del frontend
  response_type: "code",
  scope: "openid email profile"
};

const userManager = new UserManager(cognitoAuthConfig);

export async function login() {
  await userManager.signinRedirect();
}

export async function logout() {
  await userManager.signoutRedirect();
}

export async function getUser() {
  // Devuelve el usuario si ya está en storage
  const user = await userManager.getUser();
  // Si volvemos del callback (tras login), procesa el redirect
  if (!user && window.location.search.includes("code=")) {
    await userManager.signinRedirectCallback().catch(() => {});
    return await userManager.getUser();
  }
  return user;
}
