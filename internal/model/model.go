package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Permission represents a fine-grained permission action
type Permission struct {
	ID          string    `json:"id"`
	Code        string    `json:"code"`        // e.g. "users:read", "audit:export"
	Name        string    `json:"name"`        // Display name
	Category    string    `json:"category"`    // e.g. "Identity", "Audit", "Roles", "System"
	Description string    `json:"description"` // Explanation
	CreatedAt   time.Time `json:"created_at"`
}

// Role represents a collection of permissions
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	IsSystem    bool         `json:"is_system"` // System roles cannot be deleted
	Permissions []Permission `json:"permissions,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// User represents an identity within the IAM system
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	FullName     string     `json:"full_name"`
	PasswordHash string     `json:"-"` // Never expose in JSON
	Status       string     `json:"status"` // "active", "suspended", "locked"
	Roles        []Role     `json:"roles,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// AuditLog represents an immutable, tamper-evident audit log entry
type AuditLog struct {
	ID             string    `json:"id"`
	SequenceNumber int64     `json:"sequence_number"` // Monotonically increasing ID
	Timestamp      time.Time `json:"timestamp"`
	ActorID        string    `json:"actor_id"`
	ActorUsername  string    `json:"actor_username"`
	ActorIP        string    `json:"actor_ip"`
	UserAgent      string    `json:"user_agent"`
	Action         string    `json:"action"`        // e.g. "user.create", "role.update", "auth.login"
	ResourceType   string    `json:"resource_type"` // e.g. "user", "role", "audit", "session"
	ResourceID     string    `json:"resource_id"`   // Target resource ID or name
	Status         string    `json:"status"`        // "SUCCESS", "FAILURE"
	OldValues      string    `json:"old_values,omitempty"` // JSON string of state before
	NewValues      string    `json:"new_values,omitempty"` // JSON string of state after
	Reason         string    `json:"reason,omitempty"`
	PrevHash       string    `json:"prev_hash"`  // Cryptographic hash chain
	EntryHash      string    `json:"entry_hash"` // SHA-256 of this entry + prev_hash
}

// Session represents an authenticated active user session
type Session struct {
	Token       string    `json:"token"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// AuditVerificationResult contains cryptographic proof of log integrity
type AuditVerificationResult struct {
	TotalEntries   int64     `json:"total_entries"`
	VerifiedCount  int64     `json:"verified_count"`
	IsCompromised  bool      `json:"is_compromised"`
	BrokenIndex    int64     `json:"broken_index,omitempty"`
	BrokenEntryID  string    `json:"broken_entry_id,omitempty"`
	Message        string    `json:"message"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
}

// SystemStats contains overview metrics for the executive dashboard
type SystemStats struct {
	TotalUsers        int64      `json:"total_users"`
	ActiveUsers       int64      `json:"active_users"`
	SuspendedUsers    int64      `json:"suspended_users"`
	TotalRoles        int64      `json:"total_roles"`
	TotalPermissions  int64      `json:"total_permissions"`
	TotalAuditEntries int64      `json:"total_audit_entries"`
	RecentLogins24h   int64      `json:"recent_logins_24h"`
	SecurityAlerts24h int64      `json:"security_alerts_24h"`
	ChainIntegrityOk  bool       `json:"chain_integrity_ok"`
	LastAuditTime     *time.Time `json:"last_audit_time,omitempty"`
}

// ComputeAuditHash calculates deterministic SHA-256 hash of an entry chained with prevHash
func ComputeAuditHash(prevHash, tsStr, actorID, actorUsername, action, resType, resID, status, oldVal, newVal string) string {
	hasher := sha256.New()
	hasher.Write([]byte(prevHash))
	hasher.Write([]byte(tsStr))
	hasher.Write([]byte(actorID))
	hasher.Write([]byte(actorUsername))
	hasher.Write([]byte(action))
	hasher.Write([]byte(resType))
	hasher.Write([]byte(resID))
	hasher.Write([]byte(status))
	hasher.Write([]byte(oldVal))
	hasher.Write([]byte(newVal))
	return hex.EncodeToString(hasher.Sum(nil))
}
