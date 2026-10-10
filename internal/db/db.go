package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
	"github.com/pittigs/argus/internal/model"
)

// DB wraps standard sql.DB with application helpers
type DB struct {
	*sql.DB
}

// Open initializes SQLite connection with WAL mode and runs migrations
func Open(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", dbPath)
	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	rawDB.SetMaxOpenConns(25)
	rawDB.SetMaxIdleConns(5)

	database := &DB{rawDB}
	if err := database.migrate(); err != nil {
		rawDB.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	if err := database.seedDefaultData(); err != nil {
		rawDB.Close()
		return nil, fmt.Errorf("failed to seed initial data: %w", err)
	}

	if err := database.ensureDirectoryBaseline(); err != nil {
		rawDB.Close()
		return nil, fmt.Errorf("failed to ensure directory baseline: %w", err)
	}

	if err := database.ensureLifecycleBaseline(); err != nil {
		rawDB.Close()
		return nil, fmt.Errorf("failed to ensure lifecycle baseline: %w", err)
	}

	return database, nil
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS permissions (
		id TEXT PRIMARY KEY,
		code TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		category TEXT NOT NULL,
		description TEXT NOT NULL,
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS roles (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		description TEXT NOT NULL,
		is_system BOOLEAN NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS role_permissions (
		role_id TEXT NOT NULL,
		permission_id TEXT NOT NULL,
		PRIMARY KEY (role_id, permission_id),
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
		FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		full_name TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		last_login_at TEXT
	);

	CREATE TABLE IF NOT EXISTS user_roles (
		user_id TEXT NOT NULL,
		role_id TEXT NOT NULL,
		PRIMARY KEY (user_id, role_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		seq INTEGER PRIMARY KEY AUTOINCREMENT,
		id TEXT UNIQUE NOT NULL,
		timestamp TEXT NOT NULL,
		actor_id TEXT NOT NULL,
		actor_username TEXT NOT NULL,
		actor_ip TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		action TEXT NOT NULL,
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		status TEXT NOT NULL,
		old_values TEXT,
		new_values TEXT,
		reason TEXT,
		prev_hash TEXT NOT NULL,
		entry_hash TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
	CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);
	CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_username);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		username TEXT NOT NULL,
		roles_json TEXT NOT NULL,
		permissions_json TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		user_agent TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

	CREATE TABLE IF NOT EXISTS directory_config (
		id TEXT PRIMARY KEY,
		host TEXT NOT NULL DEFAULT '',
		port INTEGER NOT NULL DEFAULT 636,
		use_tls BOOLEAN NOT NULL DEFAULT 1,
		insecure_skip_verify BOOLEAN NOT NULL DEFAULT 1,
		base_dn TEXT NOT NULL DEFAULT 'DC=corp,DC=local',
		bind_dn TEXT NOT NULL DEFAULT 'CN=Argus Service,OU=ServiceAccounts,DC=corp,DC=local',
		bind_password TEXT NOT NULL DEFAULT '',
		user_container TEXT NOT NULL DEFAULT 'OU=Users,DC=corp,DC=local',
		group_container TEXT NOT NULL DEFAULT 'OU=Groups,DC=corp,DC=local',
		demo_mode BOOLEAN NOT NULL DEFAULT 1,
		updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS temporary_memberships (
		id TEXT PRIMARY KEY,
		user_sam TEXT NOT NULL,
		group_name TEXT NOT NULL,
		requested_by TEXT NOT NULL,
		reason TEXT NOT NULL,
		duration_hours INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		revoked_at TEXT,
		revoked_by TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_temp_memberships_status ON temporary_memberships(status, expires_at);

	CREATE TABLE IF NOT EXISTS approval_requests (
		id TEXT PRIMARY KEY,
		action_type TEXT NOT NULL,
		target_resource TEXT NOT NULL,
		payload_json TEXT NOT NULL,
		requested_by TEXT NOT NULL,
		reason TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		approved_by TEXT,
		resolution_notes TEXT,
		created_at TEXT NOT NULL,
		resolved_at TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);

	CREATE TABLE IF NOT EXISTS lifecycle_records (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		sam_account_name TEXT NOT NULL,
		full_name TEXT NOT NULL,
		given_name TEXT NOT NULL,
		surname TEXT NOT NULL,
		email TEXT NOT NULL,
		department TEXT NOT NULL,
		job_title TEXT NOT NULL,
		stage TEXT NOT NULL DEFAULT 'onboarded',
		start_date TEXT NOT NULL,
		end_date TEXT,
		manager TEXT,
		profile_preset TEXT NOT NULL DEFAULT 'general',
		checklist_json TEXT NOT NULL DEFAULT '{}',
		temp_password TEXT,
		notes TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_lifecycle_stage ON lifecycle_records(stage);
	CREATE INDEX IF NOT EXISTS idx_lifecycle_sam ON lifecycle_records(sam_account_name);
	`

	_, err := db.Exec(schema)
	return err
}

func (db *DB) seedDefaultData() error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil // Already initialized
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// 1. Seed Permissions
	type permDef struct {
		code, name, category, desc string
	}
	permissions := []permDef{
		{"users:read", "Benutzer anzeigen", "Identity", "Darf Benutzerdaten und Profile einsehen"},
		{"users:create", "Benutzer anlegen", "Identity", "Darf neue Identitäten im System erstellen"},
		{"users:update", "Benutzer bearbeiten", "Identity", "Darf Profile, Status und Rollen von Benutzern anpassen"},
		{"users:delete", "Benutzer löschen", "Identity", "Darf Benutzer dauerhaft aus dem System entfernen"},
		{"roles:read", "Rollen anzeigen", "Access", "Darf Rollen und zugeordnete Berechtigungen einsehen"},
		{"roles:manage", "Rollen verwalten", "Access", "Darf Rollen definieren, bearbeiten und Rechte zuweisen"},
		{"audit:read", "Audit-Log einsehen", "Audit & Compliance", "Darf das unveränderliche Audit-Log durchsuchen und analysieren"},
		{"audit:export", "Audit-Log exportieren", "Audit & Compliance", "Darf Audit-Ereignisse als JSON oder CSV exportieren"},
		{"audit:verify", "Audit-Integrität prüfen", "Audit & Compliance", "Darf die kryptografische Hash-Kette der Audit-Logs verifizieren"},
		{"system:view", "Systemstatus anzeigen", "System", "Darf Metriken und Sicherheits-Dashboards einsehen"},
		{"system:admin", "Systemverwaltung", "System", "Vollzugriff auf Systemeinstellungen und Konfiguration"},
	}

	permMap := make(map[string]string) // code -> id
	for _, p := range permissions {
		id := uuid.New().String()
		permMap[p.code] = id
		_, err := db.Exec(
			"INSERT INTO permissions (id, code, name, category, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			id, p.code, p.name, p.category, p.desc, nowStr,
		)
		if err != nil {
			return fmt.Errorf("failed to insert permission %s: %w", p.code, err)
		}
	}

	// 2. Seed Roles
	type roleDef struct {
		name, desc string
		isSystem   bool
		codes      []string
	}
	roles := []roleDef{
		{
			name:        "SuperAdmin",
			desc:        "Vollständiger Administrator-Zugriff auf alle IAM- und Audit-Funktionen",
			isSystem:    true,
			codes:       []string{"users:read", "users:create", "users:update", "users:delete", "roles:read", "roles:manage", "audit:read", "audit:export", "audit:verify", "system:view", "system:admin"},
		},
		{
			name:        "SecurityAuditor",
			desc:        "Revisionssicherer Lesezugriff für Prüfer, Auditoren und Compliance-Beauftragte",
			isSystem:    true,
			codes:       []string{"audit:read", "audit:export", "audit:verify", "users:read", "roles:read", "system:view"},
		},
		{
			name:        "UserManager",
			desc:        "Fachbereichs-Administrator zur Verwaltung von Benutzern und Teams",
			isSystem:    false,
			codes:       []string{"users:read", "users:create", "users:update", "roles:read", "audit:read", "system:view"},
		},
		{
			name:        "AuditorGuest",
			desc:        "Eingeschränkter Lesezugriff auf Audit-Logs ohne Exportrecht",
			isSystem:    false,
			codes:       []string{"audit:read", "system:view"},
		},
	}

	roleMap := make(map[string]string) // name -> id
	for _, r := range roles {
		id := uuid.New().String()
		roleMap[r.name] = id
		_, err := db.Exec(
			"INSERT INTO roles (id, name, description, is_system, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			id, r.name, r.desc, r.isSystem, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("failed to insert role %s: %w", r.name, err)
		}

		for _, code := range r.codes {
			permID, ok := permMap[code]
			if ok {
				_, err := db.Exec(
					"INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
					id, permID,
				)
				if err != nil {
					return fmt.Errorf("failed to link role %s with perm %s: %w", r.name, code, err)
				}
			}
		}
	}

	// 3. Seed Initial Users
	type userDef struct {
		username, email, fullName, password string
		roleNames                           []string
		status                              string
	}
	users := []userDef{
		{
			username: "admin",
			email:    "admin@argus.local",
			fullName: "Argus Master Admin",
			password: "admin123",
			roleNames: []string{"SuperAdmin"},
			status:   "active",
		},
		{
			username: "auditor",
			email:    "auditor@argus.local",
			fullName: "Compliance Inspector",
			password: "auditor123",
			roleNames: []string{"SecurityAuditor"},
			status:   "active",
		},
		{
			username: "sarah.connor",
			email:    "sarah.connor@argus.local",
			fullName: "Sarah Connor (HR & Team Lead)",
			password: "sarah123",
			roleNames: []string{"UserManager"},
			status:   "active",
		},
		{
			username: "maximilian.audit",
			email:    "m.audit@extern-revision.de",
			fullName: "Maximilian Prüfer (Extern)",
			password: "audit123",
			roleNames: []string{"AuditorGuest"},
			status:   "active",
		},
	}

	for _, u := range users {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		id := uuid.New().String()
		_, err = db.Exec(
			"INSERT INTO users (id, username, email, full_name, password_hash, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			id, u.username, u.email, u.fullName, string(hash), u.status, nowStr, nowStr,
		)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", u.username, err)
		}

		for _, rName := range u.roleNames {
			roleID, ok := roleMap[rName]
			if ok {
				_, err := db.Exec(
					"INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
					id, roleID,
				)
				if err != nil {
					return fmt.Errorf("failed to link user %s with role %s: %w", u.username, rName, err)
				}
			}
		}
	}

	// 4. Create Genesis Block for Audit Hash Chain
	genesisPrevHash := strings.Repeat("0", 64)
	genesisID := uuid.New().String()
	genesisAction := "system.genesis"
	genesisResource := "system"
	genesisActor := "argus-core"
	genesisNewValues := `{"event":"Argus IAM & Audit Core Engine initialized with tamper-evident cryptographic hash chain"}`
	genesisStatus := "SUCCESS"

	genesisEntryHash := model.ComputeAuditHash(
		genesisPrevHash, nowStr, "system", genesisActor,
		genesisAction, genesisResource, "core", genesisStatus,
		"", genesisNewValues,
	)

	_, err := db.Exec(`
		INSERT INTO audit_logs (
			id, timestamp, actor_id, actor_username, actor_ip, user_agent,
			action, resource_type, resource_id, status, old_values, new_values,
			reason, prev_hash, entry_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		genesisID, nowStr, "system", genesisActor, "127.0.0.1", "Argus/1.0 Engine",
		genesisAction, genesisResource, "core", genesisStatus, "",
		genesisNewValues,
		"Initial system boot & security baseline establishment",
		genesisPrevHash, genesisEntryHash,
	)
	if err != nil {
		return fmt.Errorf("failed to create genesis audit record: %w", err)
	}

	return nil
}

func (db *DB) ensureDirectoryBaseline() error {
	nowStr := time.Now().UTC().Format(time.RFC3339)

	adPerms := []struct {
		code, name, category, desc string
	}{
		{"ad:read", "AD/Samba Verzeichnis einsehen", "Active Directory", "Darf Benutzer, Gruppen und Freigaben aus AD/Samba anzeigen"},
		{"ad:users:manage", "AD/Samba Benutzer verwalten", "Active Directory", "Darf Identitäten im Domain Controller anlegen, bearbeiten und Status ändern"},
		{"ad:users:password", "AD/Samba Kennwort zurücksetzen", "Active Directory", "Darf Benutzerkennwörter im Domain Controller administrativ zurücksetzen"},
		{"ad:groups:manage", "AD/Samba Gruppen & AGDLP verwalten", "Active Directory", "Darf Sicherheitsgruppen und AGDLP-Dateifreigabegruppen anlegen und zuweisen"},
		{"ad:config", "AD/Samba Konfiguration anpassen", "Active Directory", "Darf Verbindungsparameter und Demo-Modus des Domain Controllers verwalten"},
		{"ad:jit:manage", "Befristete Berechtigungen verwalten", "Active Directory", "Darf Just-In-Time Zeitfenster für Gruppenmitgliedschaften gewähren und widerrufen"},
		{"ad:approvals:manage", "Vier-Augen-Freigaben bearbeiten", "Active Directory", "Darf privilegierte Genehmigungsanträge freigeben oder ablehnen"},
		{"ad:bulk:manage", "CSV-Massenimport durchführen", "Active Directory", "Darf Identitäten und Zuweisungen per CSV-Datei massenhaft importieren"},
		{"lifecycle:read", "HR Lifecycle einsehen", "HR Lifecycle", "Darf Mitarbeiter-Lebenszyklen und Onboarding-Status einsehen"},
		{"lifecycle:manage", "HR Onboarding/Offboarding verwalten", "HR Lifecycle", "Darf Mitarbeiter automatisiert onboarden, offboarden und transferieren"},
	}

	for _, p := range adPerms {
		var exists int
		_ = db.QueryRow("SELECT COUNT(*) FROM permissions WHERE code = ?", p.code).Scan(&exists)
		if exists == 0 {
			permID := uuid.New().String()
			_, err := db.Exec(
				"INSERT INTO permissions (id, code, name, category, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
				permID, p.code, p.name, p.category, p.desc, nowStr,
			)
			if err != nil {
				return fmt.Errorf("failed to insert AD permission %s: %w", p.code, err)
			}
		}
	}

	// Link all permissions to SuperAdmin
	var superAdminID string
	err := db.QueryRow("SELECT id FROM roles WHERE name = 'SuperAdmin'").Scan(&superAdminID)
	if err == nil {
		for _, p := range adPerms {
			var permID string
			if err := db.QueryRow("SELECT id FROM permissions WHERE code = ?", p.code).Scan(&permID); err == nil {
				_, _ = db.Exec("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", superAdminID, permID)
			}
		}
	}

	// Link ad:read, ad:users:manage, lifecycle:* to UserManager
	var userMgrID string
	err = db.QueryRow("SELECT id FROM roles WHERE name = 'UserManager'").Scan(&userMgrID)
	if err == nil {
		for _, code := range []string{"ad:read", "ad:users:manage", "ad:groups:manage", "ad:users:password", "ad:jit:manage", "ad:bulk:manage", "lifecycle:read", "lifecycle:manage"} {
			var permID string
			if err := db.QueryRow("SELECT id FROM permissions WHERE code = ?", code).Scan(&permID); err == nil {
				_, _ = db.Exec("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", userMgrID, permID)
			}
		}
	}

	// Link ad:read, lifecycle:read to SecurityAuditor
	var auditorID string
	err = db.QueryRow("SELECT id FROM roles WHERE name = 'SecurityAuditor'").Scan(&auditorID)
	if err == nil {
		for _, code := range []string{"ad:read", "lifecycle:read"} {
			var permID string
			if err := db.QueryRow("SELECT id FROM permissions WHERE code = ?", code).Scan(&permID); err == nil {
				_, _ = db.Exec("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)", auditorID, permID)
			}
		}
	}

	return nil
}

func (db *DB) ensureLifecycleBaseline() error {
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM lifecycle_records").Scan(&count)
	if count > 0 {
		return nil
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	initialRecords := []struct {
		sam, first, last, email, dept, title, stage, startDate, mgr, preset string
	}{
		{
			sam: "sarah.connor", first: "Sarah", last: "Connor", email: "s.connor@corp.local",
			dept: "Software Engineering", title: "Lead IAM Architect", stage: "onboarded",
			startDate: "2024-03-01", mgr: "Max Mustermann", preset: "it_dev",
		},
		{
			sam: "max.mustermann", first: "Max", last: "Mustermann", email: "m.mustermann@corp.local",
			dept: "IT-Security", title: "CISO / Security Lead", stage: "onboarded",
			startDate: "2023-01-15", mgr: "Vorstand", preset: "security",
		},
		{
			sam: "johann.schmidt", first: "Johann", last: "Schmidt", email: "j.schmidt@corp.local",
			dept: "Human Resources", title: "Senior HR Officer", stage: "onboarded",
			startDate: "2023-06-01", mgr: "Sarah Connor", preset: "hr_manager",
		},
		{
			sam: "elena.rostova", first: "Elena", last: "Rostova", email: "e.rostova@corp.local",
			dept: "Finance", title: "Head of Accounting", stage: "onboarded",
			startDate: "2022-11-01", mgr: "Vorstand", preset: "finance",
		},
		{
			sam: "tim.neuling", first: "Tim", last: "Neuling", email: "t.neuling@corp.local",
			dept: "Software Engineering", title: "Junior Cloud DevOps Engineer", stage: "pre_boarding",
			startDate: now.Add(7 * 24 * time.Hour).Format("2006-01-02"), mgr: "Sarah Connor", preset: "it_dev",
		},
	}

	for _, r := range initialRecords {
		id := uuid.New().String()
		fullName := fmt.Sprintf("%s %s", r.first, r.last)
		chk := map[string]any{
			"contract_signed":      map[string]any{"key": "contract_signed", "label": "Arbeitsvertrag & Verschwiegenheitserklärung", "completed": true},
			"hardware_issued":      map[string]any{"key": "hardware_issued", "label": "Hardware-Ausgabe (Notebook, YubiKey / Token)", "completed": r.stage != "pre_boarding"},
			"accounts_provisioned": map[string]any{"key": "accounts_provisioned", "label": "IAM & AD Konten provisioniert", "completed": r.stage != "pre_boarding"},
			"security_awareness":   map[string]any{"key": "security_awareness", "label": "Security-Awareness Schulung", "completed": r.stage == "onboarded"},
			"first_login_verified": map[string]any{"key": "first_login_verified", "label": "Initial-Login & Kennwortwechsel", "completed": r.stage == "onboarded"},
		}
		chkJ, _ := json.Marshal(chk)
		_, _ = db.Exec(`
			INSERT OR IGNORE INTO lifecycle_records (
				id, username, sam_account_name, full_name, given_name, surname, email,
				department, job_title, stage, start_date, manager, profile_preset,
				checklist_json, temp_password, notes, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, r.sam, r.sam, fullName, r.first, r.last, r.email,
			r.dept, r.title, r.stage, r.startDate, r.mgr, r.preset,
			string(chkJ), "", "Initialer Baseline-Mitarbeiter", nowStr, nowStr,
		)
	}

	return nil
}
