package main

import (
	"encoding/json"
	"net/http"
)

func handleSwaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerUIHTML))
}

func handleOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	spec := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Nutrico API",
			"version":     "1.0.0",
			"description": "API routes currently exposed by the service",
		},
		"paths": map[string]any{
			"/health": map[string]any{
				"get": map[string]any{
					"summary": "Health check",
					"responses": map[string]any{
						"200": map[string]any{"description": "OK"},
					},
				},
			},
			"/auth/users": map[string]any{"post": opJSON("Register", "RegisterRequest")},
			"/auth/sessions": map[string]any{"post": opJSON("Login", "LoginRequest")},
			"/auth/magic-links": map[string]any{"post": opJSON("Request magic link", "MagicRequest")},
			"/auth/oauth/google/sessions":  map[string]any{"post": op("Start Google OAuth")},
			"/auth/oauth/google/callbacks": map[string]any{"get": op("Google OAuth callback")},
			"/auth/magic-links/{token}": map[string]any{"get": opWithTokenPath("Verify magic link")},
			"/auth/users/email-verifications/{token}": map[string]any{"get": opWithTokenPath("Verify email")},
			"/auth/sessions/current/tokens": map[string]any{"put": op("Refresh token pair")},
			"/auth/sessions/current": map[string]any{"delete": op("Logout")},
			"/auth/password/reset-requests": map[string]any{"post": opJSON("Request password reset", "ForgotPasswordRequest")},
			"/auth/password": map[string]any{
				"put":   opJSON("Reset password", "ResetPasswordRequest"),
				"patch": opWithBearerJSON("Change password", "ChangePasswordRequest"),
			},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"BearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
			"schemas": map[string]any{
				"RegisterRequest": map[string]any{
					"type": "object",
					"required": []string{"email", "password"},
					"properties": map[string]any{
						"email":        map[string]any{"type": "string", "format": "email"},
						"password":     map[string]any{"type": "string", "example": "MyStr0ng!Pass"},
						"display_name": map[string]any{"type": "string", "example": "Mario Rossi"},
					},
				},
				"LoginRequest": map[string]any{
					"type": "object",
					"required": []string{"email", "password"},
					"properties": map[string]any{
						"email":    map[string]any{"type": "string", "format": "email"},
						"password": map[string]any{"type": "string", "example": "MyStr0ng!Pass"},
					},
				},
				"MagicRequest": map[string]any{
					"type": "object",
					"required": []string{"email"},
					"properties": map[string]any{
						"email": map[string]any{"type": "string", "format": "email"},
					},
				},
				"ForgotPasswordRequest": map[string]any{
					"type": "object",
					"required": []string{"email"},
					"properties": map[string]any{
						"email": map[string]any{"type": "string", "format": "email"},
					},
				},
				"ResetPasswordRequest": map[string]any{
					"type": "object",
					"required": []string{"token", "new_password"},
					"properties": map[string]any{
						"token":        map[string]any{"type": "string"},
						"new_password": map[string]any{"type": "string", "example": "MyN3w!Pass"},
					},
				},
				"ChangePasswordRequest": map[string]any{
					"type": "object",
					"required": []string{"current_password", "new_password"},
					"properties": map[string]any{
						"current_password": map[string]any{"type": "string"},
						"new_password":     map[string]any{"type": "string", "example": "MyN3w!Pass"},
					},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(spec)
}

func op(summary string) map[string]any {
	return map[string]any{
		"summary": summary,
		"responses": map[string]any{
			"200": map[string]any{"description": "OK"},
		},
	}
}

func opJSON(summary, schemaName string) map[string]any {
	v := op(summary)
	v["requestBody"] = map[string]any{
		"required": true,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": map[string]any{"$ref": "#/components/schemas/" + schemaName},
			},
		},
	}
	return v
}

func opWithBearerJSON(summary, schemaName string) map[string]any {
	v := opJSON(summary, schemaName)
	v["security"] = []map[string][]string{{"BearerAuth": {}}}
	return v
}

func opWithTokenPath(summary string) map[string]any {
	v := op(summary)
	v["parameters"] = []map[string]any{
		{
			"name":     "token",
			"in":       "path",
			"required": true,
			"schema":   map[string]any{"type": "string"},
		},
	}
	return v
}
