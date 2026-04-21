// Package dashauth provides session-based dashboard authentication for Cyphera servers.
//
// Two modes:
//   - Dev mode (apiKey=""): all requests pass through, no auth required
//   - Production mode (apiKey set): dashboard login required, session cookie used
//
// Programmatic API access via Authorization: Bearer header is always supported.
//
// Future hardening (not implemented — tracked, not hacked):
//   - OIDC/SSO integration
//   - Multi-user RBAC
//   - Session persistence across restarts
//   - Refresh tokens
package dashauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cookieName      = "cyphera_session"
	sessionDuration = 8 * time.Hour
	cleanupInterval = 15 * time.Minute
	maxLoginPerMin  = 5
	tokenBytes      = 32
)

// Session represents an authenticated dashboard session.
type Session struct {
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	RemoteIP  string
}

// loginAttempt tracks a failed login for rate limiting.
type loginAttempt struct {
	at time.Time
}

// DashAuth handles dashboard and API authentication.
type DashAuth struct {
	apiKey  string // empty = dev mode (no auth)
	devMode bool   // explicit dev mode flag (overrides apiKey check)
	tls     bool   // set Secure flag on cookies

	sessions sync.Map // token -> *Session

	loginMu       sync.Mutex
	loginAttempts map[string][]loginAttempt // ip -> attempts
}

// New creates a DashAuth instance.
// apiKey="" means dev mode (no authentication required).
// tls=true sets the Secure flag on session cookies.
func New(apiKey string, tls bool) *DashAuth {
	d := &DashAuth{
		apiKey:        apiKey,
		tls:           tls,
		loginAttempts: make(map[string][]loginAttempt),
	}
	go d.cleanupLoop()
	return d
}

// NewDevMode creates a DashAuth that skips all authentication.
// Use this when the server is in --dev mode.
func NewDevMode() *DashAuth {
	d := &DashAuth{
		devMode:       true,
		loginAttempts: make(map[string][]loginAttempt),
	}
	return d
}

// IsDevMode returns true when authentication is disabled.
func (d *DashAuth) IsDevMode() bool {
	return d.devMode || d.apiKey == ""
}

// RegisterRoutes adds /auth/* endpoints to the mux.
func (d *DashAuth) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/login", d.handleLogin)
	mux.HandleFunc("POST /auth/logout", d.handleLogout)
	mux.HandleFunc("GET /auth/status", d.handleStatus)
}

// RequireAPIAuth protects API endpoints.
// Accepts Bearer token (programmatic) OR valid session cookie (dashboard).
// In dev mode, all requests pass through.
func (d *DashAuth) RequireAPIAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.IsDevMode() {
			next(w, r)
			return
		}

		// Check Bearer token (programmatic access: curl, KMIP clients, etc.)
		if auth := r.Header.Get("Authorization"); auth != "" {
			token := strings.TrimPrefix(auth, "Bearer ")
			if token != auth && subtle.ConstantTimeCompare([]byte(token), []byte(d.apiKey)) == 1 {
				next(w, r)
				return
			}
		}

		// Check session cookie (dashboard access)
		if cookie, err := r.Cookie(cookieName); err == nil {
			if d.validSession(cookie.Value) {
				next(w, r)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}
}

// --- Auth endpoints ---

func (d *DashAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if d.IsDevMode() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "dev_mode": true})
		return
	}

	// Rate limit
	ip := extractIP(r)
	if !d.allowLogin(ip) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "too many login attempts"})
		return
	}

	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.APIKey), []byte(d.apiKey)) != 1 {
		d.recordFailedLogin(ip)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid API key"})
		return
	}

	// Create session
	token := d.createSession(ip)

	// Set cookie
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionDuration.Seconds()),
	}
	if d.tls {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (d *DashAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		d.sessions.Delete(cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "logged out"})
}

func (d *DashAuth) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if d.IsDevMode() {
		json.NewEncoder(w).Encode(map[string]any{
			"authenticated": true,
			"dev_mode":      true,
		})
		return
	}

	authenticated := false
	if cookie, err := r.Cookie(cookieName); err == nil {
		authenticated = d.validSession(cookie.Value)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"authenticated": authenticated,
		"dev_mode":      false,
	})
}

// --- Session management ---

func (d *DashAuth) createSession(ip string) string {
	tokenBytes := make([]byte, tokenBytes)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	now := time.Now()
	d.sessions.Store(token, &Session{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(sessionDuration),
		RemoteIP:  ip,
	})

	return token
}

func (d *DashAuth) validSession(token string) bool {
	val, ok := d.sessions.Load(token)
	if !ok {
		return false
	}
	sess := val.(*Session)
	if time.Now().After(sess.ExpiresAt) {
		d.sessions.Delete(token)
		return false
	}
	return true
}

func (d *DashAuth) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	for range ticker.C {
		now := time.Now()
		d.sessions.Range(func(key, value any) bool {
			sess := value.(*Session)
			if now.After(sess.ExpiresAt) {
				d.sessions.Delete(key)
			}
			return true
		})

		// Clean up old login attempts
		d.loginMu.Lock()
		cutoff := now.Add(-time.Minute)
		for ip, attempts := range d.loginAttempts {
			var recent []loginAttempt
			for _, a := range attempts {
				if a.at.After(cutoff) {
					recent = append(recent, a)
				}
			}
			if len(recent) == 0 {
				delete(d.loginAttempts, ip)
			} else {
				d.loginAttempts[ip] = recent
			}
		}
		d.loginMu.Unlock()
	}
}

// --- Login rate limiting ---

func (d *DashAuth) allowLogin(ip string) bool {
	d.loginMu.Lock()
	defer d.loginMu.Unlock()

	cutoff := time.Now().Add(-time.Minute)
	attempts := d.loginAttempts[ip]
	var recent []loginAttempt
	for _, a := range attempts {
		if a.at.After(cutoff) {
			recent = append(recent, a)
		}
	}
	d.loginAttempts[ip] = recent

	return len(recent) < maxLoginPerMin
}

func (d *DashAuth) recordFailedLogin(ip string) {
	d.loginMu.Lock()
	defer d.loginMu.Unlock()
	d.loginAttempts[ip] = append(d.loginAttempts[ip], loginAttempt{at: time.Now()})
}

// --- Helpers ---

func extractIP(r *http.Request) string {
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
