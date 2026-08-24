// Package auth implements the lightweight role model: viewer < operator < admin.
// It exists so approvals always have an identity; it is deliberately simple.
package auth

import (
	"context"
	"net/http"
	"strings"
)

type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleOperator
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "admin"
	case RoleOperator:
		return "operator"
	case RoleViewer:
		return "viewer"
	default:
		return "anonymous"
	}
}

type Config struct {
	Enabled       bool
	AdminToken    string
	OperatorToken string
	ViewerToken   string
}

func (r Role) AtLeast(other Role) bool { return r >= other }

// Principal identifies WHO performed a request, for audit fields such as
// approvals.decided_by. Role alone is authorization; Name is attribution.
type Principal struct {
	Role Role
	Name string
}

type ctxKey struct{}

// WithPrincipal attaches the authenticated principal to the request context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, &p)
}

// FromContext returns the principal (nil when auth middleware did not run).
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// Identify maps a bearer token to a principal (role + stable display name).
func (c Config) Identify(r *http.Request) *Principal {
	h := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if !c.Enabled {
		// local/dev mode: full access, attributed explicitly
		return &Principal{Role: RoleAdmin, Name: "local-admin"}
	}
	switch {
	case token != "" && token == c.AdminToken:
		return &Principal{Role: RoleAdmin, Name: "admin"}
	case token != "" && token == c.OperatorToken:
		return &Principal{Role: RoleOperator, Name: "operator"}
	case token != "" && token == c.ViewerToken:
		return &Principal{Role: RoleViewer, Name: "viewer"}
	default:
		return nil
	}
}

// Middleware rejects requests below the required role and stores the
// principal for handlers (audit attribution).
func (c Config) Middleware(required Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := c.Identify(r)
		if p != nil && p.Role.AtLeast(required) {
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), *p)))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized: missing or insufficient credentials"}`))
	})
}
