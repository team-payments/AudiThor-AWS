import { UserManager } from "oidc-client-ts";

const cognitoAuthConfig = {
  authority: "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ATD5cVZi3",
  client_id: "2faon57u5n6sm1ilv7ncj1us53",
  redirect_uri: "https://d38k4y82pqltc.cloudfront.net",
  response_type: "code",
  scope: "openid email profile"
};

export const userManager = new UserManager(cognitoAuthConfig);

export function login() {
  userManager.signinRedirect();
}

export function logout() {
  userManager.signoutRedirect();
}

export async function getUser() {
  return await userManager.getUser();
}