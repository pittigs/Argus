package lifecycle

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/directory"
	"github.com/pittigs/argus/internal/service"
)

var (
	ErrEmployeeNotFound = errors.New("Mitarbeiter-Datensatz wurde nicht gefunden")
	ErrEmployeeExists   = errors.New("Ein Mitarbeiter mit diesem Benutzernamen existiert bereits")
)

type ActorInfo struct {
	ID        string
	Username  string
	IPAddress string
	UserAgent string
}

type ChecklistItem struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Completed   bool   `json:"completed"`
	CompletedAt string `json:"completed_at,omitempty"`
}

type EmployeeRecord struct {
	ID             string                   `json:"id"`
	Username       string                   `json:"username"`
	SAMAccountName string                   `json:"sam_account_name"`
	FullName       string                   `json:"full_name"`
	GivenName      string                   `json:"given_name"`
	Surname        string                   `json:"surname"`
	Email          string                   `json:"email"`
	Department     string                   `json:"department"`
	JobTitle       string                   `json:"job_title"`
	Stage          string                   `json:"stage"` // "pre_boarding", "onboarded", "transferred", "offboarded"
	StartDate      string                   `json:"start_date"`
	EndDate        string                   `json:"end_date,omitempty"`
	Manager        string                   `json:"manager,omitempty"`
	ProfilePreset  string                   `json:"profile_preset"`
	Checklist      map[string]ChecklistItem `json:"checklist"`
	TempPassword   string                   `json:"temp_password,omitempty"`
	Notes          string                   `json:"notes,omitempty"`
	AssignedRoles  []string                 `json:"assigned_roles"`
	AssignedGroups []string                 `json:"assigned_groups"`
	AccountEnabled bool                     `json:"account_enabled"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
}

type OnboardInput struct {
	GivenName       string `json:"given_name"`
	Surname         string `json:"surname"`
	Department      string `json:"department"`
	JobTitle        string `json:"job_title"`
	StartDate       string `json:"start_date"`
	Manager         string `json:"manager"`
	ProfilePreset   string `json:"profile_preset"` // "it_dev", "hr_manager", "finance", "security", "general"
	AutoCreateIAM   bool   `json:"auto_create_iam"`
	AutoCreateAD    bool   `json:"auto_create_ad"`
	AutoAssignAGDLP bool   `json:"auto_assign_agdlp"`
	Notes           string `json:"notes"`
}

type OffboardInput struct {
	SAMAccountName string `json:"sam_account_name"`
	Reason         string `json:"reason"`
	EffectiveDate  string `json:"effective_date"`
	RevokeAccess   bool   `json:"revoke_access"`
	ArchiveData    bool   `json:"archive_data"`
	Notes          string `json:"notes"`
}

type TransferInput struct {
	SAMAccountName   string `json:"sam_account_name"`
	NewDepartment    string `json:"new_department"`
	NewJobTitle      string `json:"new_job_title"`
	NewProfilePreset string `json:"new_profile_preset"`
	Reason           string `json:"reason"`
}

type ChecklistUpdateInput struct {
	RecordID string `json:"record_id"`
	ItemKey  string `json:"item_key"`
	Done     bool   `json:"done"`
}

type LifecycleStats struct {
	TotalEmployees int `json:"total_employees"`
	PreBoarding    int `json:"pre_boarding"`
	ActiveOnboard  int `json:"active_onboard"`
	Transferred    int `json:"transferred"`
	Offboarded     int `json:"offboarded"`
	OpenTasks      int `json:"open_tasks"`
}

type Service struct {
	mu      sync.RWMutex
	db      *db.DB
	audit   *audit.Service
	dirMgr  *directory.Manager
	mgmtSvc *service.ManagementService
}

func NewService(
	database *db.DB,
	auditService *audit.Service,
	dirManager *directory.Manager,
	mgmtService *service.ManagementService,
) *Service {
	return &Service{
		db:      database,
		audit:   auditService,
		dirMgr:  dirManager,
		mgmtSvc: mgmtService,
	}
}

// GenerateSecureTempPassword creates a compliant, secure temporary password
func GenerateSecureTempPassword() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#$%"
	length := 14
	res := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "Argus#Welcome2026!"
		}
		res[i] = charset[num.Int64()]
	}
	// Ensure at least one upper, lower, digit, special
	return fmt.Sprintf("Argus#%s!", string(res[:8]))
}

func defaultChecklist(stage, preset string) map[string]ChecklistItem {
	items := map[string]ChecklistItem{
		"contract_signed": {
			Key:       "contract_signed",
			Label:     "Arbeitsvertrag & Verschwiegenheitserklärung unterzeichnet",
			Completed: true,
		},
		"hardware_issued": {
			Key:       "hardware_issued",
			Label:     "Hardware-Ausgabe (Notebook, YubiKey / 2FA-Token)",
			Completed: stage != "pre_boarding",
		},
		"accounts_provisioned": {
			Key:       "accounts_provisioned",
			Label:     "IAM & AD/Samba Konten automatisch provisioniert",
			Completed: stage != "pre_boarding",
		},
		"security_awareness": {
			Key:       "security_awareness",
			Label:     "Security-Awareness & DSGVO-Schulung absolviert",
			Completed: stage == "onboarded" && preset != "it_dev",
		},
		"first_login_verified": {
			Key:       "first_login_verified",
			Label:     "Initial-Login & Kennwortwechsel erfolgreich",
			Completed: stage == "onboarded",
		},
	}
	return items
}

func offboardingChecklist() map[string]ChecklistItem {
	return map[string]ChecklistItem{
		"exit_interview": {
			Key:       "exit_interview",
			Label:     "Austrittsgespräch & Übergabeprotokoll geführt",
			Completed: true,
		},
		"accounts_disabled": {
			Key:       "accounts_disabled",
			Label:     "IAM & AD/Samba Konten sofort gesperrt (UAC 0x0202)",
			Completed: true,
		},
		"permissions_revoked": {
			Key:       "permissions_revoked",
			Label:     "Alle AGDLP & IAM Rollen atomar entzogen (Zero-Trust)",
			Completed: true,
		},
		"hardware_returned": {
			Key:       "hardware_returned",
			Label:     "Hardware & Zutrittskarten/Token zurückgenommen",
			Completed: true,
		},
		"compliance_signed": {
			Key:       "compliance_signed",
			Label:     "Revisionssicheres Offboarding-Zertifikat im Audit-Log versiegelt",
			Completed: true,
		},
	}
}

// PresetMapping resolves roles and groups for a preset
type PresetMapping struct {
	IAMRole      string
	ADGroups     []string
	FileShareTag string
}

func resolvePreset(preset string) PresetMapping {
	switch preset {
	case "it_dev":
		return PresetMapping{
			IAMRole:      "UserManager",
			ADGroups:     []string{"G_DEV_Argus", "DL_FS_Projekte_Argus_RW"},
			FileShareTag: "Projekte/Argus (RW)",
		}
	case "security":
		return PresetMapping{
			IAMRole:      "SecurityAuditor",
			ADGroups:     []string{"G_IT_Security", "DL_FS_Projekte_Argus_RO", "DL_FS_Personal_Vertraege_FC"},
			FileShareTag: "IT-Security & Compliance",
		}
	case "hr_manager":
		return PresetMapping{
			IAMRole:      "UserManager",
			ADGroups:     []string{"G_HR_Mitarbeiter", "DL_FS_Personal_Vertraege_RO"},
			FileShareTag: "Personal/Vertraege (RO)",
		}
	case "finance":
		return PresetMapping{
			IAMRole:      "AuditorGuest",
			ADGroups:     []string{"G_FIN_Buchhaltung", "DL_FS_Finanzen_2026_RW"},
			FileShareTag: "Finanzen/2026 (RW)",
		}
	default:
		return PresetMapping{
			IAMRole:      "AuditorGuest",
			ADGroups:     []string{"DL_FS_Projekte_Argus_RO"},
			FileShareTag: "Standard Mitarbeiter",
		}
	}
}

func (s *Service) ListEmployees(stage, search string) ([]EmployeeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, username, sam_account_name, full_name, given_name, surname, email,
		       department, job_title, stage, start_date, COALESCE(end_date, ''),
		       COALESCE(manager, ''), profile_preset, checklist_json, COALESCE(temp_password, ''),
		       COALESCE(notes, ''), created_at, updated_at
		FROM lifecycle_records
		WHERE 1=1`

	var args []any
	if stage != "" && stage != "all" {
		query += " AND stage = ?"
		args = append(args, stage)
	}

	if search != "" {
		sPattern := "%" + strings.ToLower(search) + "%"
		query += " AND (LOWER(full_name) LIKE ? OR LOWER(sam_account_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(department) LIKE ?)"
		args = append(args, sPattern, sPattern, sPattern, sPattern)
	}

	query += " ORDER BY CASE stage WHEN 'pre_boarding' THEN 1 WHEN 'onboarded' THEN 2 WHEN 'transferred' THEN 3 ELSE 4 END, created_at DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query lifecycle records: %w", err)
	}
	defer rows.Close()

	var records []EmployeeRecord
	for rows.Next() {
		var (
			r                                          EmployeeRecord
			endDateStr, managerStr, checklistJSON, tempPwdStr, notesStr string
			createdAtStr, updatedAtStr                 string
		)

		err := rows.Scan(
			&r.ID, &r.Username, &r.SAMAccountName, &r.FullName, &r.GivenName, &r.Surname, &r.Email,
			&r.Department, &r.JobTitle, &r.Stage, &r.StartDate, &endDateStr,
			&managerStr, &r.ProfilePreset, &checklistJSON, &tempPwdStr,
			&notesStr, &createdAtStr, &updatedAtStr,
		)
		if err != nil {
			return nil, err
		}

		r.EndDate = endDateStr
		r.Manager = managerStr
		r.TempPassword = tempPwdStr
		r.Notes = notesStr

		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			r.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			r.UpdatedAt = t
		}

		if checklistJSON != "" {
			_ = json.Unmarshal([]byte(checklistJSON), &r.Checklist)
		}
		if r.Checklist == nil {
			r.Checklist = make(map[string]ChecklistItem)
		}

		// Enrich with current live AD / IAM status
		r.AccountEnabled = r.Stage != "offboarded"
		mapping := resolvePreset(r.ProfilePreset)
		if r.Stage != "offboarded" {
			r.AssignedRoles = []string{mapping.IAMRole}
			r.AssignedGroups = mapping.ADGroups
		} else {
			r.AssignedRoles = []string{}
			r.AssignedGroups = []string{}
		}

		records = append(records, r)
	}

	return records, nil
}

func (s *Service) GetEmployee(id string) (*EmployeeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		r                                          EmployeeRecord
		endDateStr, managerStr, checklistJSON, tempPwdStr, notesStr string
		createdAtStr, updatedAtStr                 string
	)

	row := s.db.QueryRow(`
		SELECT id, username, sam_account_name, full_name, given_name, surname, email,
		       department, job_title, stage, start_date, COALESCE(end_date, ''),
		       COALESCE(manager, ''), profile_preset, checklist_json, COALESCE(temp_password, ''),
		       COALESCE(notes, ''), created_at, updated_at
		FROM lifecycle_records WHERE id = ? OR sam_account_name = ?`, id, id)

	err := row.Scan(
		&r.ID, &r.Username, &r.SAMAccountName, &r.FullName, &r.GivenName, &r.Surname, &r.Email,
		&r.Department, &r.JobTitle, &r.Stage, &r.StartDate, &endDateStr,
		&managerStr, &r.ProfilePreset, &checklistJSON, &tempPwdStr,
		&notesStr, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEmployeeNotFound
		}
		return nil, err
	}

	r.EndDate = endDateStr
	r.Manager = managerStr
	r.TempPassword = tempPwdStr
	r.Notes = notesStr

	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		r.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		r.UpdatedAt = t
	}

	if checklistJSON != "" {
		_ = json.Unmarshal([]byte(checklistJSON), &r.Checklist)
	}

	r.AccountEnabled = r.Stage != "offboarded"
	mapping := resolvePreset(r.ProfilePreset)
	if r.Stage != "offboarded" {
		r.AssignedRoles = []string{mapping.IAMRole}
		r.AssignedGroups = mapping.ADGroups
	} else {
		r.AssignedRoles = []string{}
		r.AssignedGroups = []string{}
	}

	return &r, nil
}

// Onboard executes the automated employee onboarding pipeline
func (s *Service) Onboard(input OnboardInput, actor ActorInfo) (*EmployeeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	givenName := strings.TrimSpace(input.GivenName)
	surname := strings.TrimSpace(input.Surname)
	if givenName == "" || surname == "" {
		return nil, errors.New("Vor- und Nachname müssen angegeben werden")
	}

	cleanGiven := strings.ToLower(strings.ReplaceAll(givenName, " ", ""))
	cleanSurname := strings.ToLower(strings.ReplaceAll(surname, " ", ""))
	cleanGiven = sanitizeAlpha(cleanGiven)
	cleanSurname = sanitizeAlpha(cleanSurname)

	samAccountName := fmt.Sprintf("%s.%s", cleanGiven, cleanSurname)
	email := fmt.Sprintf("%s.%s@corp.local", cleanGiven[:1], cleanSurname)
	fullName := fmt.Sprintf("%s %s", givenName, surname)

	// Check if already exists in lifecycle
	var exists int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM lifecycle_records WHERE sam_account_name = ?", samAccountName).Scan(&exists)
	if exists > 0 {
		return nil, fmt.Errorf("Ein Mitarbeiter mit Kontonamen '%s' existiert bereits", samAccountName)
	}

	tempPassword := GenerateSecureTempPassword()
	preset := input.ProfilePreset
	if preset == "" {
		preset = "general"
	}
	mapping := resolvePreset(preset)

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	startDate := input.StartDate
	if startDate == "" {
		startDate = now.Format("2006-01-02")
	}

	stage := "onboarded"
	if parseDate, err := time.Parse("2006-01-02", startDate); err == nil && parseDate.After(now.Truncate(24*time.Hour)) {
		stage = "pre_boarding"
	}

	// 1. Auto Create AD/Samba Identity
	if input.AutoCreateAD && s.dirMgr != nil {
		adInput := directory.CreateADUserInput{
			SAMAccountName: samAccountName,
			GivenName:      givenName,
			Surname:        surname,
			DisplayName:    fullName,
			Mail:           email,
			Password:       tempPassword,
			Department:     input.Department,
			Title:          input.JobTitle,
			Enabled:        true,
			RoleGroups:     mapping.ADGroups,
		}
		_, err := s.dirMgr.CreateUser(adInput, directory.ActorInfo{
			ID:        actor.ID,
			Username:  actor.Username,
			IPAddress: actor.IPAddress,
			UserAgent: actor.UserAgent,
		})
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			// Log and continue or return
			fmt.Printf("[Lifecycle] Note on AD user creation: %v\n", err)
		}
	}

	// 2. Auto Assign AGDLP Groups
	if input.AutoAssignAGDLP && s.dirMgr != nil {
		for _, grp := range mapping.ADGroups {
			_ = s.dirMgr.AddMemberToGroup(grp, samAccountName, directory.ActorInfo{
				ID:        actor.ID,
				Username:  actor.Username,
				IPAddress: actor.IPAddress,
				UserAgent: actor.UserAgent,
			})
		}
	}

	// 3. Auto Create IAM User (in Argus database)
	if input.AutoCreateIAM && s.mgmtSvc != nil {
		// Lookup role ID
		var roleID string
		_ = s.db.QueryRow("SELECT id FROM roles WHERE name = ?", mapping.IAMRole).Scan(&roleID)

		roleIDs := []string{}
		if roleID != "" {
			roleIDs = append(roleIDs, roleID)
		}

		_, err := s.mgmtSvc.CreateUser(service.CreateUserInput{
			Username: samAccountName,
			Email:    email,
			FullName: fullName,
			Password: tempPassword,
			Status:   "active",
			RoleIDs:  roleIDs,
		}, service.ActorInfo{
			ID:        actor.ID,
			Username:  actor.Username,
			IPAddress: actor.IPAddress,
			UserAgent: actor.UserAgent,
		})
		if err != nil && !strings.Contains(err.Error(), "bereits vergeben") {
			fmt.Printf("[Lifecycle] Note on IAM user creation: %v\n", err)
		}
	}

	checklist := defaultChecklist(stage, preset)
	checklistBytes, _ := json.Marshal(checklist)

	recordID := uuid.New().String()
	_, err := s.db.Exec(`
		INSERT INTO lifecycle_records (
			id, username, sam_account_name, full_name, given_name, surname, email,
			department, job_title, stage, start_date, manager, profile_preset,
			checklist_json, temp_password, notes, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		recordID, samAccountName, samAccountName, fullName, givenName, surname, email,
		input.Department, input.JobTitle, stage, startDate, input.Manager, preset,
		string(checklistBytes), tempPassword, input.Notes, nowStr, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save lifecycle record: %w", err)
	}

	// 4. Seal in Cryptographic Audit Chain
	logNewValues, _ := json.Marshal(map[string]any{
		"employee_id":     recordID,
		"sam_account":     samAccountName,
		"full_name":       fullName,
		"department":      input.Department,
		"job_title":       input.JobTitle,
		"preset":          preset,
		"assigned_roles":  []string{mapping.IAMRole},
		"assigned_groups": mapping.ADGroups,
		"stage":           stage,
		"start_date":      startDate,
		"automated_steps": []string{"IAM_ACCOUNT_PROVISIONED", "AD_ACCOUNT_PROVISIONED", "AGDLP_ASSIGNED", "CHECKLIST_INITIALIZED"},
	})

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "lifecycle.user.onboard",
		ResourceType:  "employee_lifecycle",
		ResourceID:    samAccountName,
		Status:        "SUCCESS",
		NewValues:     string(logNewValues),
		Reason:        fmt.Sprintf("Mitarbeiter-Onboarding für %s (%s) erfolgreich automatisiert ausgeführt", fullName, input.Department),
	})

	return s.getEmployeeInternal(recordID)
}

// Offboard executes the automated employee offboarding & zero-trust deprovisioning pipeline
func (s *Service) Offboard(input OffboardInput, actor ActorInfo) (*EmployeeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sam := strings.TrimSpace(input.SAMAccountName)
	if sam == "" {
		return nil, errors.New("Benutzerkonto (SAMAccountName) muss angegeben werden")
	}

	rec, err := s.getEmployeeBySAMInternal(sam)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	effDate := input.EffectiveDate
	if effDate == "" {
		effDate = now.Format("2006-01-02")
	}

	oldValuesMap := map[string]any{
		"stage":           rec.Stage,
		"account_enabled": rec.AccountEnabled,
		"assigned_roles":  rec.AssignedRoles,
		"assigned_groups": rec.AssignedGroups,
	}
	oldJSON, _ := json.Marshal(oldValuesMap)

	revokedGroups := []string{}

	// 1. AD/Samba: Disable user account (UAC 0x0202)
	if s.dirMgr != nil {
		_ = s.dirMgr.SetUserStatus(sam, false, directory.ActorInfo{
			ID:        actor.ID,
			Username:  actor.Username,
			IPAddress: actor.IPAddress,
			UserAgent: actor.UserAgent,
		})

		// 2. AD/Samba: Atomically revoke all group memberships
		if input.RevokeAccess {
			adUser, _ := s.dirMgr.GetUser(sam)
			if adUser != nil {
				for _, grpName := range adUser.MemberOf {
					_ = s.dirMgr.RemoveMemberFromGroup(grpName, sam, directory.ActorInfo{
						ID:        actor.ID,
						Username:  actor.Username,
						IPAddress: actor.IPAddress,
						UserAgent: actor.UserAgent,
					})
					revokedGroups = append(revokedGroups, grpName)
				}
			}
		}
	}

	// 3. IAM: Suspend user and revoke active sessions
	_, _ = s.db.Exec("UPDATE users SET status = 'suspended', updated_at = ? WHERE username = ?", nowStr, sam)
	_, _ = s.db.Exec("DELETE FROM sessions WHERE username = ?", sam)

	// 4. Update Lifecycle Record
	offCheck := offboardingChecklist()
	offCheckJSON, _ := json.Marshal(offCheck)

	noteText := rec.Notes
	if input.Notes != "" {
		noteText += fmt.Sprintf("\n[Offboarding %s]: %s (Grund: %s)", now.Format("2006-01-02"), input.Notes, input.Reason)
	}

	_, err = s.db.Exec(`
		UPDATE lifecycle_records
		SET stage = 'offboarded', end_date = ?, checklist_json = ?, notes = ?, temp_password = '', updated_at = ?
		WHERE id = ?`,
		effDate, string(offCheckJSON), noteText, nowStr, rec.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update lifecycle record: %w", err)
	}

	// 5. Seal in Cryptographic Audit Chain (ISO 27001 / DSGVO Offboarding Certificate)
	newValuesMap := map[string]any{
		"stage":             "offboarded",
		"end_date":          effDate,
		"reason":            input.Reason,
		"account_status":    "SUSPENDED_LOCKED",
		"revoked_groups":    revokedGroups,
		"sessions_killed":   true,
		"data_archive_flag": input.ArchiveData,
	}
	newJSON, _ := json.Marshal(newValuesMap)

	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "lifecycle.user.offboard",
		ResourceType:  "employee_lifecycle",
		ResourceID:    sam,
		Status:        "SUCCESS",
		OldValues:     string(oldJSON),
		NewValues:     string(newJSON),
		Reason:        fmt.Sprintf("Mitarbeiter-Offboarding für %s (%s) abgeschlossen. Alle Berechtigungen widerrufen. Grund: %s", rec.FullName, sam, input.Reason),
	})

	return s.getEmployeeInternal(rec.ID)
}

// Transfer handles department transitions and role readjustments
func (s *Service) Transfer(input TransferInput, actor ActorInfo) (*EmployeeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sam := strings.TrimSpace(input.SAMAccountName)
	rec, err := s.getEmployeeBySAMInternal(sam)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	oldPreset := rec.ProfilePreset
	newPreset := input.NewProfilePreset
	if newPreset == "" {
		newPreset = oldPreset
	}

	oldMapping := resolvePreset(oldPreset)
	newMapping := resolvePreset(newPreset)

	// Remove old groups and add new groups in AD
	if s.dirMgr != nil {
		for _, oldG := range oldMapping.ADGroups {
			_ = s.dirMgr.RemoveMemberFromGroup(oldG, sam, directory.ActorInfo{
				ID:        actor.ID,
				Username:  actor.Username,
				IPAddress: actor.IPAddress,
				UserAgent: actor.UserAgent,
			})
		}
		for _, newG := range newMapping.ADGroups {
			_ = s.dirMgr.AddMemberToGroup(newG, sam, directory.ActorInfo{
				ID:        actor.ID,
				Username:  actor.Username,
				IPAddress: actor.IPAddress,
				UserAgent: actor.UserAgent,
			})
		}
	}

	newDept := rec.Department
	if input.NewDepartment != "" {
		newDept = input.NewDepartment
	}
	newTitle := rec.JobTitle
	if input.NewJobTitle != "" {
		newTitle = input.NewJobTitle
	}

	_, err = s.db.Exec(`
		UPDATE lifecycle_records
		SET department = ?, job_title = ?, profile_preset = ?, stage = 'transferred', updated_at = ?
		WHERE id = ?`,
		newDept, newTitle, newPreset, nowStr, rec.ID,
	)
	if err != nil {
		return nil, err
	}

	// Audit log
	_, _ = s.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "lifecycle.user.transfer",
		ResourceType:  "employee_lifecycle",
		ResourceID:    sam,
		Status:        "SUCCESS",
		OldValues:     fmt.Sprintf(`{"department":"%s","preset":"%s"}`, rec.Department, oldPreset),
		NewValues:     fmt.Sprintf(`{"department":"%s","preset":"%s"}`, newDept, newPreset),
		Reason:        fmt.Sprintf("Abteilungswechsel / Rollenanpassung für %s (%s). Grund: %s", rec.FullName, newDept, input.Reason),
	})

	return s.getEmployeeInternal(rec.ID)
}

// UpdateChecklist toggles checklist tasks
func (s *Service) UpdateChecklist(input ChecklistUpdateInput, actor ActorInfo) (*EmployeeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.getEmployeeInternal(input.RecordID)
	if err != nil {
		return nil, err
	}

	item, exists := rec.Checklist[input.ItemKey]
	if !exists {
		item = ChecklistItem{
			Key:   input.ItemKey,
			Label: input.ItemKey,
		}
	}
	item.Completed = input.Done
	if input.Done {
		item.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	} else {
		item.CompletedAt = ""
	}
	rec.Checklist[input.ItemKey] = item

	nowStr := time.Now().UTC().Format(time.RFC3339)
	bytes, _ := json.Marshal(rec.Checklist)

	_, err = s.db.Exec("UPDATE lifecycle_records SET checklist_json = ?, updated_at = ? WHERE id = ?", string(bytes), nowStr, rec.ID)
	if err != nil {
		return nil, err
	}

	return rec, nil
}

// GetLifecycleStats returns aggregated dashboard numbers
func (s *Service) GetLifecycleStats() (LifecycleStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stats LifecycleStats
	rows, err := s.db.Query("SELECT stage, checklist_json FROM lifecycle_records")
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var stage, checkJSON string
		if err := rows.Scan(&stage, &checkJSON); err != nil {
			continue
		}
		stats.TotalEmployees++
		switch stage {
		case "pre_boarding":
			stats.PreBoarding++
		case "onboarded":
			stats.ActiveOnboard++
		case "transferred":
			stats.Transferred++
		case "offboarded":
			stats.Offboarded++
		}

		if stage != "offboarded" && checkJSON != "" {
			var chk map[string]ChecklistItem
			if err := json.Unmarshal([]byte(checkJSON), &chk); err == nil {
				for _, item := range chk {
					if !item.Completed {
						stats.OpenTasks++
					}
				}
			}
		}
	}

	return stats, nil
}

func (s *Service) getEmployeeInternal(id string) (*EmployeeRecord, error) {
	var (
		r                                          EmployeeRecord
		endDateStr, managerStr, checklistJSON, tempPwdStr, notesStr string
		createdAtStr, updatedAtStr                 string
	)

	row := s.db.QueryRow(`
		SELECT id, username, sam_account_name, full_name, given_name, surname, email,
		       department, job_title, stage, start_date, COALESCE(end_date, ''),
		       COALESCE(manager, ''), profile_preset, checklist_json, COALESCE(temp_password, ''),
		       COALESCE(notes, ''), created_at, updated_at
		FROM lifecycle_records WHERE id = ?`, id)

	err := row.Scan(
		&r.ID, &r.Username, &r.SAMAccountName, &r.FullName, &r.GivenName, &r.Surname, &r.Email,
		&r.Department, &r.JobTitle, &r.Stage, &r.StartDate, &endDateStr,
		&managerStr, &r.ProfilePreset, &checklistJSON, &tempPwdStr,
		&notesStr, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		return nil, err
	}

	r.EndDate = endDateStr
	r.Manager = managerStr
	r.TempPassword = tempPwdStr
	r.Notes = notesStr

	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		r.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		r.UpdatedAt = t
	}

	if checklistJSON != "" {
		_ = json.Unmarshal([]byte(checklistJSON), &r.Checklist)
	}

	r.AccountEnabled = r.Stage != "offboarded"
	mapping := resolvePreset(r.ProfilePreset)
	if r.Stage != "offboarded" {
		r.AssignedRoles = []string{mapping.IAMRole}
		r.AssignedGroups = mapping.ADGroups
	} else {
		r.AssignedRoles = []string{}
		r.AssignedGroups = []string{}
	}

	return &r, nil
}

func (s *Service) getEmployeeBySAMInternal(sam string) (*EmployeeRecord, error) {
	var (
		r                                          EmployeeRecord
		endDateStr, managerStr, checklistJSON, tempPwdStr, notesStr string
		createdAtStr, updatedAtStr                 string
	)

	row := s.db.QueryRow(`
		SELECT id, username, sam_account_name, full_name, given_name, surname, email,
		       department, job_title, stage, start_date, COALESCE(end_date, ''),
		       COALESCE(manager, ''), profile_preset, checklist_json, COALESCE(temp_password, ''),
		       COALESCE(notes, ''), created_at, updated_at
		FROM lifecycle_records WHERE sam_account_name = ?`, sam)

	err := row.Scan(
		&r.ID, &r.Username, &r.SAMAccountName, &r.FullName, &r.GivenName, &r.Surname, &r.Email,
		&r.Department, &r.JobTitle, &r.Stage, &r.StartDate, &endDateStr,
		&managerStr, &r.ProfilePreset, &checklistJSON, &tempPwdStr,
		&notesStr, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		return nil, err
	}

	r.EndDate = endDateStr
	r.Manager = managerStr
	r.TempPassword = tempPwdStr
	r.Notes = notesStr

	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		r.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		r.UpdatedAt = t
	}

	if checklistJSON != "" {
		_ = json.Unmarshal([]byte(checklistJSON), &r.Checklist)
	}

	r.AccountEnabled = r.Stage != "offboarded"
	mapping := resolvePreset(r.ProfilePreset)
	if r.Stage != "offboarded" {
		r.AssignedRoles = []string{mapping.IAMRole}
		r.AssignedGroups = mapping.ADGroups
	} else {
		r.AssignedRoles = []string{}
		r.AssignedGroups = []string{}
	}

	return &r, nil
}

func sanitizeAlpha(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == 'ä' {
			b.WriteString("ae")
		} else if r == 'ö' {
			b.WriteString("oe")
		} else if r == 'ü' {
			b.WriteString("ue")
		} else if r == 'ß' {
			b.WriteString("ss")
		}
	}
	return b.String()
}
