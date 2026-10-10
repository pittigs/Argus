package service

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/auth"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/model"
)

var (
	ErrUserNotFound     = errors.New("Benutzer wurde nicht gefunden")
	ErrRoleNotFound     = errors.New("Rolle wurde nicht gefunden")
	ErrSystemRoleLocked = errors.New("Systemrollen können nicht gelöscht oder umbenannt werden")
	ErrCannotDeleteSelf = errors.New("Das eigene Administratorkonto kann nicht gelöscht werden")
	ErrDuplicateUser    = errors.New("Benutzername oder E-Mail ist bereits vergeben")
)

type ActorInfo struct {
	ID        string
	Username  string
	IPAddress string
	UserAgent string
}

type ManagementService struct {
	db    *db.DB
	audit *audit.Service
}

func NewManagementService(database *db.DB, auditService *audit.Service) *ManagementService {
	return &ManagementService{
		db:    database,
		audit: auditService,
	}
}

// ----------------- USERS -----------------

type CreateUserInput struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	FullName string   `json:"full_name"`
	Password string   `json:"password"`
	Status   string   `json:"status"`
	RoleIDs  []string `json:"role_ids"`
}

type UpdateUserInput struct {
	Email    string   `json:"email"`
	FullName string   `json:"full_name"`
	Password string   `json:"password,omitempty"`
	Status   string   `json:"status"`
	RoleIDs  []string `json:"role_ids"`
}

func (s *ManagementService) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(`
		SELECT id, username, email, full_name, status, created_at, updated_at, COALESCE(last_login_at, '')
		FROM users
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}

	type userRow struct {
		u            model.User
		createdAtStr string
		updatedAtStr string
		lastLoginStr string
	}
	var rawRows []userRow

	for rows.Next() {
		var r userRow
		if err := rows.Scan(&r.u.ID, &r.u.Username, &r.u.Email, &r.u.FullName, &r.u.Status, &r.createdAtStr, &r.updatedAtStr, &r.lastLoginStr); err != nil {
			rows.Close()
			return nil, err
		}
		rawRows = append(rawRows, r)
	}
	rows.Close()

	var users []model.User
	for _, r := range rawRows {
		if t, err := time.Parse(time.RFC3339, r.createdAtStr); err == nil {
			r.u.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, r.updatedAtStr); err == nil {
			r.u.UpdatedAt = t
		}
		if r.lastLoginStr != "" {
			if t, err := time.Parse(time.RFC3339, r.lastLoginStr); err == nil {
				r.u.LastLoginAt = &t
			}
		}

		roles, err := s.getUserRoles(r.u.ID)
		if err != nil {
			return nil, err
		}
		r.u.Roles = roles
		users = append(users, r.u)
	}

	return users, nil
}

func (s *ManagementService) GetUser(id string) (*model.User, error) {
	var u model.User
	var createdAtStr, updatedAtStr, lastLoginStr string

	err := s.db.QueryRow(`
		SELECT id, username, email, full_name, status, created_at, updated_at, COALESCE(last_login_at, '')
		FROM users WHERE id = ?`, id).Scan(
		&u.ID, &u.Username, &u.Email, &u.FullName, &u.Status, &createdAtStr, &updatedAtStr, &lastLoginStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		u.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		u.UpdatedAt = t
	}
	if lastLoginStr != "" {
		if t, err := time.Parse(time.RFC3339, lastLoginStr); err == nil {
			u.LastLoginAt = &t
		}
	}

	roles, err := s.getUserRoles(u.ID)
	if err != nil {
		return nil, err
	}
	u.Roles = roles
	return &u, nil
}

func (s *ManagementService) getUserRoles(userID string) ([]model.Role, error) {
	rows, err := s.db.Query(`
		SELECT r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []model.Role
	for rows.Next() {
		var r model.Role
		var cStr, uStr string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.IsSystem, &cStr, &uStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, cStr); err == nil {
			r.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, uStr); err == nil {
			r.UpdatedAt = t
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func (s *ManagementService) CreateUser(in CreateUserInput, actor ActorInfo) (*model.User, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	in.FullName = strings.TrimSpace(in.FullName)

	if in.Username == "" || in.Email == "" || in.Password == "" {
		return nil, errors.New("Benutzername, E-Mail und Kennwort sind Pflichtfelder")
	}

	if in.Status == "" {
		in.Status = "active"
	}

	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", in.Username, in.Email).Scan(&count)
	if count > 0 {
		return nil, ErrDuplicateUser
	}

	pwdHash, err := auth.HashPassword(in.Password)
	if err != nil {
		return nil, fmt.Errorf("password hash error: %w", err)
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	userID := uuid.New().String()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO users (id, username, email, full_name, password_hash, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, in.Username, in.Email, in.FullName, pwdHash, in.Status, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("insert user error: %w", err)
	}

	for _, roleID := range in.RoleIDs {
		if strings.TrimSpace(roleID) == "" {
			continue
		}
		_, err = tx.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", userID, roleID)
		if err != nil {
			return nil, fmt.Errorf("assign role error: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	createdUser, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}

	// Audit log
	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "user.create",
		ResourceType:  "user",
		ResourceID:    createdUser.Username,
		Status:        "SUCCESS",
		NewValues: map[string]interface{}{
			"id":        createdUser.ID,
			"username":  createdUser.Username,
			"email":     createdUser.Email,
			"full_name": createdUser.FullName,
			"status":    createdUser.Status,
			"roles":     createdUser.Roles,
		},
		Reason: "Neue Benutzeridentität angelegt",
	})

	return createdUser, nil
}

func (s *ManagementService) UpdateUser(id string, in UpdateUserInput, actor ActorInfo) (*model.User, error) {
	existing, err := s.GetUser(id)
	if err != nil {
		return nil, err
	}

	in.Email = strings.TrimSpace(in.Email)
	in.FullName = strings.TrimSpace(in.FullName)
	if in.Status == "" {
		in.Status = existing.Status
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if strings.TrimSpace(in.Password) != "" {
		pwdHash, err := auth.HashPassword(in.Password)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`
			UPDATE users SET email = ?, full_name = ?, status = ?, password_hash = ?, updated_at = ?
			WHERE id = ?`, in.Email, in.FullName, in.Status, pwdHash, nowStr, id)
		if err != nil {
			return nil, err
		}
	} else {
		_, err = tx.Exec(`
			UPDATE users SET email = ?, full_name = ?, status = ?, updated_at = ?
			WHERE id = ?`, in.Email, in.FullName, in.Status, nowStr, id)
		if err != nil {
			return nil, err
		}
	}

	if in.RoleIDs != nil {
		_, err = tx.Exec("DELETE FROM user_roles WHERE user_id = ?", id)
		if err != nil {
			return nil, err
		}
		for _, roleID := range in.RoleIDs {
			if strings.TrimSpace(roleID) == "" {
				continue
			}
			_, err = tx.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", id, roleID)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	updatedUser, err := s.GetUser(id)
	if err != nil {
		return nil, err
	}

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "user.update",
		ResourceType:  "user",
		ResourceID:    updatedUser.Username,
		Status:        "SUCCESS",
		OldValues: map[string]interface{}{
			"email":     existing.Email,
			"full_name": existing.FullName,
			"status":    existing.Status,
			"roles":     existing.Roles,
		},
		NewValues: map[string]interface{}{
			"email":          updatedUser.Email,
			"full_name":      updatedUser.FullName,
			"status":         updatedUser.Status,
			"roles":          updatedUser.Roles,
			"password_reset": strings.TrimSpace(in.Password) != "",
		},
		Reason: "Benutzerprofil und Zugriffsrechte modifiziert",
	})

	return updatedUser, nil
}

func (s *ManagementService) DeleteUser(id string, actor ActorInfo) error {
	existing, err := s.GetUser(id)
	if err != nil {
		return err
	}

	if existing.ID == actor.ID {
		return ErrCannotDeleteSelf
	}

	var remainingAdmins int
	_ = s.db.QueryRow(`
		SELECT COUNT(DISTINCT u.id)
		FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		JOIN roles r ON ur.role_id = r.id
		WHERE r.name = 'SuperAdmin' AND u.status = 'active' AND u.id != ?`, id).Scan(&remainingAdmins)

	isTargetSuperAdmin := false
	for _, r := range existing.Roles {
		if r.Name == "SuperAdmin" {
			isTargetSuperAdmin = true
			break
		}
	}
	if isTargetSuperAdmin && remainingAdmins == 0 {
		return errors.New("Der letzte aktive SuperAdmin darf nicht gelöscht werden")
	}

	_, err = s.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "user.delete",
		ResourceType:  "user",
		ResourceID:    existing.Username,
		Status:        "SUCCESS",
		OldValues: map[string]interface{}{
			"id":        existing.ID,
			"username":  existing.Username,
			"email":     existing.Email,
			"full_name": existing.FullName,
			"roles":     existing.Roles,
		},
		Reason: "Benutzerkonto permanent gelöscht",
	})

	return nil
}

// ----------------- ROLES & PERMISSIONS -----------------

type CreateRoleInput struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permission_ids"`
}

type UpdateRoleInput struct {
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permission_ids"`
}

func (s *ManagementService) ListPermissions() ([]model.Permission, error) {
	rows, err := s.db.Query(`
		SELECT id, code, name, category, description, created_at
		FROM permissions
		ORDER BY category, code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		var cStr string
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Category, &p.Description, &cStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, cStr); err == nil {
			p.CreatedAt = t
		}
		perms = append(perms, p)
	}
	return perms, nil
}

func (s *ManagementService) ListRoles() ([]model.Role, error) {
	rows, err := s.db.Query(`
		SELECT id, name, description, is_system, created_at, updated_at
		FROM roles
		ORDER BY is_system DESC, name ASC`)
	if err != nil {
		return nil, err
	}

	type roleRow struct {
		r    model.Role
		cStr string
		uStr string
	}
	var rawRoles []roleRow

	for rows.Next() {
		var rr roleRow
		if err := rows.Scan(&rr.r.ID, &rr.r.Name, &rr.r.Description, &rr.r.IsSystem, &rr.cStr, &rr.uStr); err != nil {
			rows.Close()
			return nil, err
		}
		rawRoles = append(rawRoles, rr)
	}
	rows.Close()

	var roles []model.Role
	for _, rr := range rawRoles {
		if t, err := time.Parse(time.RFC3339, rr.cStr); err == nil {
			rr.r.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, rr.uStr); err == nil {
			rr.r.UpdatedAt = t
		}
		perms, err := s.getRolePermissions(rr.r.ID)
		if err != nil {
			return nil, err
		}
		rr.r.Permissions = perms
		roles = append(roles, rr.r)
	}

	return roles, nil
}

func (s *ManagementService) GetRole(id string) (*model.Role, error) {
	var r model.Role
	var cStr, uStr string
	err := s.db.QueryRow(`
		SELECT id, name, description, is_system, created_at, updated_at
		FROM roles WHERE id = ?`, id).Scan(&r.ID, &r.Name, &r.Description, &r.IsSystem, &cStr, &uStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}

	if t, err := time.Parse(time.RFC3339, cStr); err == nil {
		r.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, uStr); err == nil {
		r.UpdatedAt = t
	}

	perms, err := s.getRolePermissions(r.ID)
	if err != nil {
		return nil, err
	}
	r.Permissions = perms
	return &r, nil
}

func (s *ManagementService) getRolePermissions(roleID string) ([]model.Permission, error) {
	rows, err := s.db.Query(`
		SELECT p.id, p.code, p.name, p.category, p.description, p.created_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = ?
		ORDER BY p.category, p.code`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		var cStr string
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Category, &p.Description, &cStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, cStr); err == nil {
			p.CreatedAt = t
		}
		perms = append(perms, p)
	}
	return perms, nil
}

func (s *ManagementService) CreateRole(in CreateRoleInput, actor ActorInfo) (*model.Role, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, errors.New("Rollenname ist erforderlich")
	}

	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM roles WHERE LOWER(name) = LOWER(?)", in.Name).Scan(&count)
	if count > 0 {
		return nil, errors.New("Eine Rolle mit diesem Namen existiert bereits")
	}

	roleID := uuid.New().String()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO roles (id, name, description, is_system, created_at, updated_at)
		VALUES (?, ?, ?, 0, ?, ?)`,
		roleID, in.Name, in.Description, nowStr, nowStr,
	)
	if err != nil {
		return nil, err
	}

	for _, pID := range in.PermissionIDs {
		if strings.TrimSpace(pID) == "" {
			continue
		}
		_, err = tx.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", roleID, pID)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	createdRole, err := s.GetRole(roleID)
	if err != nil {
		return nil, err
	}

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "role.create",
		ResourceType:  "role",
		ResourceID:    createdRole.Name,
		Status:        "SUCCESS",
		NewValues: map[string]interface{}{
			"id":          createdRole.ID,
			"name":        createdRole.Name,
			"description": createdRole.Description,
			"permissions": createdRole.Permissions,
		},
		Reason: "Neue Berechtigungsrolle definiert",
	})

	return createdRole, nil
}

func (s *ManagementService) UpdateRole(id string, in UpdateRoleInput, actor ActorInfo) (*model.Role, error) {
	existing, err := s.GetRole(id)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE roles SET description = ?, updated_at = ? WHERE id = ?", in.Description, nowStr, id)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec("DELETE FROM role_permissions WHERE role_id = ?", id)
	if err != nil {
		return nil, err
	}

	for _, pID := range in.PermissionIDs {
		if strings.TrimSpace(pID) == "" {
			continue
		}
		_, err = tx.Exec("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", id, pID)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	updatedRole, err := s.GetRole(id)
	if err != nil {
		return nil, err
	}

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "role.update",
		ResourceType:  "role",
		ResourceID:    updatedRole.Name,
		Status:        "SUCCESS",
		OldValues: map[string]interface{}{
			"description": existing.Description,
			"permissions": existing.Permissions,
		},
		NewValues: map[string]interface{}{
			"description": updatedRole.Description,
			"permissions": updatedRole.Permissions,
		},
		Reason: "Rollenberechtigungen modifiziert",
	})

	return updatedRole, nil
}

func (s *ManagementService) DeleteRole(id string, actor ActorInfo) error {
	existing, err := s.GetRole(id)
	if err != nil {
		return err
	}

	if existing.IsSystem {
		return ErrSystemRoleLocked
	}

	_, err = s.db.Exec("DELETE FROM roles WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "role.delete",
		ResourceType:  "role",
		ResourceID:    existing.Name,
		Status:        "SUCCESS",
		OldValues: map[string]interface{}{
			"id":          existing.ID,
			"name":        existing.Name,
			"description": existing.Description,
			"permissions": existing.Permissions,
		},
		Reason: "Rolle und Zuweisungen gelöscht",
	})

	return nil
}

// ----------------- SYSTEM STATS -----------------

func (s *ManagementService) GetStats() (*model.SystemStats, error) {
	var stats model.SystemStats

	_ = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&stats.TotalUsers)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users WHERE status = 'active'").Scan(&stats.ActiveUsers)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users WHERE status != 'active'").Scan(&stats.SuspendedUsers)

	_ = s.db.QueryRow("SELECT COUNT(*) FROM roles").Scan(&stats.TotalRoles)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&stats.TotalPermissions)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&stats.TotalAuditEntries)

	since24h := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login' AND status = 'SUCCESS' AND timestamp >= ?", since24h).Scan(&stats.RecentLogins24h)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE status = 'FAILURE' AND timestamp >= ?", since24h).Scan(&stats.SecurityAlerts24h)

	var lastAuditStr string
	err := s.db.QueryRow("SELECT timestamp FROM audit_logs ORDER BY seq DESC LIMIT 1").Scan(&lastAuditStr)
	if err == nil {
		if t, err := time.Parse(time.RFC3339, lastAuditStr); err == nil {
			stats.LastAuditTime = &t
		}
	}

	verifyRes, err := s.audit.VerifyChain()
	if err == nil && !verifyRes.IsCompromised {
		stats.ChainIntegrityOk = true
	} else {
		stats.ChainIntegrityOk = false
	}

	return &stats, nil
}
