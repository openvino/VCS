package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type KeycloakTokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int32  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type CognitoLikeResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int32  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		panic(fmt.Sprintf("%s env var is required", k))
	}
	return v
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func tokenHandler(kcTokenURL, clientID, clientSecret string) http.HandlerFunc {
	hc := &http.Client{Timeout: 10 * time.Second}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
			return
		}

		_ = r.ParseForm()
		grantType := r.FormValue("grant_type")
		if grantType == "" {
			// tu mock hoy casi ni usa el body, pero ponemos default razonable
			grantType = "password"
		}

		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)

		switch grantType {
		case "password":
			u, p, ok := r.BasicAuth()
			if !ok || u == "" || p == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid credential"})
				return
			}
			form.Set("grant_type", "password")
			form.Set("username", u)
			form.Set("password", p)
			// para que Keycloak te dé id_token también
			form.Set("scope", "openid")

		case "client_credentials":
			form.Set("grant_type", "client_credentials")

		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "unsupported grant_type"})
			return
		}

		req, _ := http.NewRequest(http.MethodPost, kcTokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := hc.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"message": "upstream error"})
			return
		}
		defer resp.Body.Close()

		b, _ := io.ReadAll(resp.Body)

		var kc KeycloakTokenResponse
		_ = json.Unmarshal(b, &kc)

		// si keycloak devuelve error, lo pasamos claro
		if resp.StatusCode >= 400 {
			msg := kc.ErrorDescription
			if msg == "" {
				msg = string(b)
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": msg})
			return
		}

		// sanity
		if kc.AccessToken == "" {
			writeJSON(w, http.StatusBadGateway, map[string]string{"message": "invalid upstream response"})
			return
		}
		if kc.TokenType == "" {
			kc.TokenType = "Bearer"
		}

		out := CognitoLikeResponse{
			AccessToken:  kc.AccessToken,
			ExpiresIn:    kc.ExpiresIn,
			IDToken:      kc.IDToken,
			RefreshToken: kc.RefreshToken,
			TokenType:    kc.TokenType,
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func main() {
	hostURL := mustEnv("HOST_URL") // ej 0.0.0.0:8095
	kcBase := mustEnv("KEYCLOAK_BASE_URL")
	realm := mustEnv("KEYCLOAK_REALM")
	clientID := mustEnv("KEYCLOAK_CLIENT_ID")
	clientSecret := mustEnv("KEYCLOAK_CLIENT_SECRET")

	if !strings.HasPrefix(kcBase, "http://") && !strings.HasPrefix(kcBase, "https://") {
		panic(errors.New("KEYCLOAK_BASE_URL must start with http:// or https://"))
	}

	kcTokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(kcBase, "/"),
		url.PathEscape(realm),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/cognito/oauth2/token", tokenHandler(kcTokenURL, clientID, clientSecret))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "not found"})
	})

	fmt.Printf("listening on %s\n", hostURL)
	if err := http.ListenAndServe(hostURL, mux); err != nil {
		panic(err)
	}
}
