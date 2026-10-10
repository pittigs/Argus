package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/model"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("ungültiger Benutzername oder Kennwort")
	ErrAccountSuspended   = errors.New("Benutzerkonto ist gesperrt oder inaktiv")
	ErrAccountLocked      = errors.New("Konto ist aufgrund zu vieler fehlgeschlagener Anmeldeversuche temporär gesperrt (15 Minuten)")
	ErrWeakPassword       = errors.New("das Kennwort erfüllt nicht die Mindestanforderungen (mindestens 10 Zeichen, Groß-/Kleinbuchstaben, Ziffer und Sonderzeichen)")
	ErrSessionExpired     = errors.New("Sitzung ist abgelaufen oder ungültig")
	ErrForbidden          = errors.New("unzureichende Berechtigungen")
)

type LoginAttemptTracker struct {
	mu       sync.Mutex
	attempts map[string]int
	lockedAt map[string]time.Time
}

func newLoginAttemptTracker() *LoginAttemptTracker {
	return &LoginAttemptTracker{
		attempts: make(map[string]int),
		lockedAt: make(map[string]time.Time),
	}
}

func cleanIP(ip string) string {
	if h, _, err := net.SplitHostPort(ip); err == nil {
		return h
	}
	return ip
}

func (t *LoginAttemptTracker) keys(username, ip string) (string, string) {
	return "user:" + strings.ToLower(username), "ip:" + cleanIP(ip)
}

func (t *LoginAttemptTracker) IsLocked(username, ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	userKey, ipKey := t.keys(username, ip)
	if lockTime, ok := t.lockedAt[userKey]; ok {
		if time.Since(lockTime) <= 15*time.Minute {
			return true
		}
		delete(t.lockedAt, userKey)
		delete(t.attempts, userKey)
	}
	if lockTime, ok := t.lockedAt[ipKey]; ok {
		if time.Since(lockTime) <= 15*time.Minute {
			return true
		}
		delete(t.lockedAt, ipKey)
		delete(t.attempts, ipKey)
	}
	return false
}

func (t *LoginAttemptTracker) RecordFailure(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	userKey, ipKey := t.keys(username, ip)
	t.attempts[userKey]++
	if t.attempts[userKey] >= 5 {
		t.lockedAt[userKey] = time.Now()
	}
	t.attempts[ipKey]++
	if t.attempts[ipKey] >= 50 {
		t.lockedAt[ipKey] = time.Now()
	}
}

func (t *LoginAttemptTracker) Clear(username, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	userKey, ipKey := t.keys(username, ip)
	delete(t.attempts, userKey)
	delete(t.lockedAt, userKey)
	delete(t.attempts, ipKey)
	delete(t.lockedAt, ipKey)
}

type Service struct {
	db      *db.DB
	tracker *LoginAttemptTracker
}

func NewService(database *db.DB) *Service {
	return &Service{
		db:      database,
		tracker: newLoginAttemptTracker(),
	}
}

// HashPassword hashes a raw password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares password against hash
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// GenerateToken creates secure cryptographically random token
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Authenticate verifies user credentials and creates a persistent session
func (s *Service) Authenticate(username, password, ipAddress, userAgent string) (*model.Session, *model.User, error) {
	if s.tracker.IsLocked(username, ipAddress) {
		return nil, nil, ErrAccountLocked
	}

	var user model.User
	var passwordHash string
	var cStr, uStr, lStr string

	err := s.db.QueryRow(`
		SELECT id, username, email, full_name, password_hash, status, created_at, updated_at, COALESCE(last_login_at, '')
		FROM users
		WHERE LOWER(username) = LOWER(?)`, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.FullName,
		&passwordHash, &user.Status, &cStr, &uStr, &lStr,
	)
	if err != nil {
		s.tracker.RecordFailure(username, ipAddress)
		if err == sql.ErrNoRows {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	if t, err := time.Parse(time.RFC3339, cStr); err == nil {
		user.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, uStr); err == nil {
		user.UpdatedAt = t
	}
	if lStr != "" {
		if t, err := time.Parse(time.RFC3339, lStr); err == nil {
			user.LastLoginAt = &t
		}
	}

	if user.Status != "active" {
		return nil, nil, ErrAccountSuspended
	}

	if !CheckPassword(password, passwordHash) {
		s.tracker.RecordFailure(username, ipAddress)
		return nil, nil, ErrInvalidCredentials
	}

	// Login successful: reset failed attempt counter
	s.tracker.Clear(username, ipAddress)

	roles, permissions, err := s.GetUserRolesAndPermissions(user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch user roles: %w", err)
	}

	token, err := GenerateToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	nowStr := now.Format(time.RFC3339)
	expiresStr := expiresAt.Format(time.RFC3339)

	rolesJSON, _ := json.Marshal(roles)
	permsJSON, _ := json.Marshal(permissions)

	_, err = s.db.Exec(`
		INSERT INTO sessions (
			token, user_id, username, roles_json, permissions_json,
			expires_at, created_at, ip_address, user_agent
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, user.ID, user.Username, string(rolesJSON), string(permsJSON),
		expiresStr, nowStr, ipAddress, userAgent,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to persist session: %w", err)
	}

	// Update last login
	_, _ = s.db.Exec("UPDATE users SET last_login_at = ? WHERE id = ?", nowStr, user.ID)

	session := &model.Session{
		Token:       token,
		UserID:      user.ID,
		Username:    user.Username,
		Roles:       roles,
		Permissions: permissions,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
	}

	return session, &user, nil
}

// GetUserRolesAndPermissions returns role names and flattened permission codes
func (s *Service) GetUserRolesAndPermissions(userID string) ([]string, []string, error) {
	rows, err := s.db.Query(`
		SELECT r.name, p.code
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		LEFT JOIN role_permissions rp ON r.id = rp.role_id
		LEFT JOIN permissions p ON rp.permission_id = p.id
		WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	roleSet := make(map[string]bool)
	permSet := make(map[string]bool)

	for rows.Next() {
		var roleName string
		var permCode sql.NullString
		if err := rows.Scan(&roleName, &permCode); err != nil {
			return nil, nil, err
		}
		if roleName != "" {
			roleSet[roleName] = true
		}
		if permCode.Valid && permCode.String != "" {
			permSet[permCode.String] = true
		}
	}

	var roles []string
	for r := range roleSet {
		roles = append(roles, r)
	}
	var permissions []string
	for p := range permSet {
		permissions = append(permissions, p)
	}

	return roles, permissions, nil
}

// ValidateSession verifies token against database and returns active Session
func (s *Service) ValidateSession(token string) (*model.Session, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrSessionExpired
	}

	var sess model.Session
	var rolesJSON, permsJSON string
	var expiresStr, createdStr string

	err := s.db.QueryRow(`
		SELECT token, user_id, username, roles_json, permissions_json,
		       expires_at, created_at, ip_address, user_agent
		FROM sessions
		WHERE token = ?`, token).Scan(
		&sess.Token, &sess.UserID, &sess.Username, &rolesJSON, &permsJSON,
		&expiresStr, &createdStr, &sess.IPAddress, &sess.UserAgent,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionExpired
		}
		return nil, err
	}

	if t, err := time.Parse(time.RFC3339, expiresStr); err == nil {
		sess.ExpiresAt = t
	}
	if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
		sess.CreatedAt = t
	}

	if time.Now().UTC().After(sess.ExpiresAt) {
		_ = s.RevokeSession(token)
		return nil, ErrSessionExpired
	}

	_ = json.Unmarshal([]byte(rolesJSON), &sess.Roles)
	_ = json.Unmarshal([]byte(permsJSON), &sess.Permissions)

	return &sess, nil
}

// RevokeSession removes the session token
func (s *Service) RevokeSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

// HasPermission checks if the session contains the required permission or SuperAdmin role
func HasPermission(session *model.Session, requiredPermission string) bool {
	if session == nil {
		return false
	}
	for _, role := range session.Roles {
		if role == "SuperAdmin" {
			return true
		}
	}
	for _, perm := range session.Permissions {
		if perm == requiredPermission {
			return true
		}
	}
	return false
}

// ExtractToken retrieves token from Bearer header or Cookie
func ExtractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	if cookie, err := r.Cookie("argus_session"); err == nil {
		return cookie.Value
	}
	return ""
}

// ValidatePasswordComplexity enforces robust passwords (OWASP recommendation)
func ValidatePasswordComplexity(pwd string) error {
	if len(pwd) < 10 {
		return ErrWeakPassword
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range pwd {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrWeakPassword
	}
	return nil
}

// IsDefaultPassword checks whether account is still using an insecure default seed password
func IsDefaultPassword(pwd string) bool {
	l := strings.ToLower(pwd)
	return l == "admin123" || l == "auditor123" || l == "sarah123"
}

// ChangePassword updates user password with complexity verification
func (s *Service) ChangePassword(username, oldPassword, newPassword string) error {
	if err := ValidatePasswordComplexity(newPassword); err != nil {
		return err
	}
	if IsDefaultPassword(newPassword) {
		return errors.New("das neue Kennwort darf kein Standardkennwort sein")
	}

	var storedHash string
	err := s.db.QueryRow("SELECT password_hash FROM users WHERE LOWER(username) = LOWER(?)", username).Scan(&storedHash)
	if err != nil {
		return ErrInvalidCredentials
	}

	if !CheckPassword(oldPassword, storedHash) {
		return ErrInvalidCredentials
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	_, err = s.db.Exec("UPDATE users SET password_hash = ?, updated_at = ? WHERE LOWER(username) = LOWER(?)", newHash, nowStr, username)
	return err
}

