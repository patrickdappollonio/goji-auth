package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/zenazn/goji/web"
)

var (
	defaultMessage      = "Protected"
	defaultErrorMessage = http.StatusText(http.StatusUnauthorized)
)

type AuthConfig struct {
	Username            string
	Password            string
	Message             string
	UnauthorizedMessage string
}

func WithUserPass(username, password string) AuthConfig {
	return AuthConfig{
		Username:            username,
		Password:            password,
		Message:             defaultMessage,
		UnauthorizedMessage: defaultErrorMessage,
	}
}

func WithUserPassMessage(username, password, message string) AuthConfig {
	return AuthConfig{
		Username:            username,
		Password:            password,
		Message:             message,
		UnauthorizedMessage: defaultErrorMessage,
	}
}

func Auth(config AuthConfig) func(c *web.C, h http.Handler) http.Handler {
	if strings.TrimSpace(config.Username) == "" || strings.TrimSpace(config.Password) == "" {
		panic("auth: username and/or password are empty")
	}

	return func(c *web.C, h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if authorizationHash := strings.TrimSpace(r.Header.Get("Authorization")); len(authorizationHash) > 0 {
				// Check if the message is empty
				if len(strings.TrimSpace(config.Message)) == 0 {
					config.Message = defaultMessage
				}

				// Check if the error message is empty
				if len(strings.TrimSpace(config.UnauthorizedMessage)) == 0 {
					config.UnauthorizedMessage = defaultErrorMessage
				}

				// Split to get both parts: the type and the hash
				credentials := strings.Split(authorizationHash, " ")

				// Check if we get 2 elements and the first one is "Basic" as in "Basic Auth"
				if len(credentials) != 2 || credentials[0] != "Basic" {
					unauthorized(config.Message, config.UnauthorizedMessage, w)
					return
				}

				// Decode the hash coming as Base64
				authCode, err := base64.StdEncoding.DecodeString(credentials[1])
				if err != nil {
					unauthorized(config.Message, config.UnauthorizedMessage, w)
					return
				}

				// Split the string where the semicolon is found
				if dataSlice := strings.Split(string(authCode[:]), ":"); len(dataSlice) == 2 {
					if dataSlice[0] == config.Username && dataSlice[1] == config.Password {
						h.ServeHTTP(w, r)
						return
					}
				}

				unauthorized(config.Message, config.UnauthorizedMessage, w)
				return
			} else {
				unauthorized(config.Message, config.UnauthorizedMessage, w)
			}
		}

		return http.HandlerFunc(fn)
	}
}

func unauthorized(message, unauthorized string, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, message))
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
