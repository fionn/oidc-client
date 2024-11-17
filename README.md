# OIDC Client

Simple OIDC client to demonstrate authenticating a user's email address.

Currently it only supports Google.

## Setup

Create a Google OAuth2 application with the OpenID and email scopes and add `http://127.0.0.1:5556/` as redirect URI.

Export `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and run `main.go`.
This will print a URL and spin up a web server. Visit the URL and consent to sharing your account data and you'll be redirected to the local server, which will parse and validate the redirect and print the email address and subject identifier.
