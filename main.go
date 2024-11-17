package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Identity struct {
	UUID         string `json:"uuid"`
	EmailAddress string `json:"email"`
}

func main() {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	address := "127.0.0.1:5556"
	callbackPath := "/auth/google/callback"
	issuer := "https://accounts.google.com"

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}

	conf := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://" + address + callbackPath,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"}, // We could add "profile".
	}

	state := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier()
	pkceSecret := oauth2.GenerateVerifier()

	url := conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkceSecret))
	log.Printf("Visit\n\n\t%s\n\nto authenticate\n", url)

	verifier := provider.Verifier(&oidc.Config{ClientID: conf.ClientID})

	http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {

		validate := func() (*Identity, error) {
			if r.URL.Query().Get("state") != state {
				return nil, errors.New("unexpected state")
			}

			oauth2Token, err := conf.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pkceSecret))
			if err != nil {
				return nil, err
			}

			// Throw this away, we have all we need in the ID token.
			oauth2Token.AccessToken = ""

			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				return nil, errors.New("missing id_token field")
			}

			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				return nil, err
			}

			if idToken.Nonce != nonce {
				return nil, errors.New("unexpected nonce")
			}

			var claims struct {
				AuthorizedParty string `json:"azp"`
				Email           string `json:"email"`
				EmailVerified   bool   `json:"email_verified"`
			}

			if err := idToken.Claims(&claims); err != nil {
				return nil, err
			}

			// Sanity check.
			if claims.AuthorizedParty != clientID {
				return nil, errors.New("unexpected authorized party")
			}

			if !claims.EmailVerified {
				return nil, errors.New("email address is not verified by issuer")
			}

			identity := Identity{
				UUID:         idToken.Subject,
				EmailAddress: claims.Email,
			}

			return &identity, nil
		}

		identity, err := validate()
		if err != nil {
			log.Print(err)
			http.Error(w, "Error", http.StatusBadRequest)
			return
		}

		log.Printf("Received callback from %s (%s)", identity.UUID, identity.EmailAddress)

		data, err := json.MarshalIndent(*identity, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
