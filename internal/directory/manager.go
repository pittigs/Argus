package directory

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/db"
)

// ActorInfo holds identity of whoever triggered the action
type ActorInfo struct {
	ID        string
	Username  string
	IPAddress string
	UserAgent string
}

// Manager orchestrates directory operations and seals every change in the SHA-256 audit log
type Manager struct {
	mu           sync.RWMutex
	db           *db.DB
	audit        *audit.Service
	config       DirectoryConfig
	mockProvider *MockProvider
	ldapProvider *LDAPProvider
}

// NewManager initializes the directory manager and loads persistent config
func NewManager(database *db.DB, auditService *audit.Service) (*Manager, error) {
	mgr := &Manager{
		db:           database,
		audit:        auditService,
		mockProvider: NewMockProvider(),
	}

	if err := mgr.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load directory configuration: %w", err)
	}

	return mgr, nil
}

func (m *Manager) loadConfig() error {
	var (
		id, host, baseDN, bindDN, bindPwd, userCont, groupCont string
		port                                                  int
		useTLS, skipVerify, demoMode                          bool
		updatedAtStr                                          string
	)

	row := m.db.QueryRow(`
		SELECT id, host, port, use_tls, insecure_skip_verify, base_dn, bind_dn, bind_password,
		       user_container, group_container, demo_mode, updated_at
		FROM directory_config WHERE id = 'default'`)

	err := row.Scan(&id, &host, &port, &useTLS, &skipVerify, &baseDN, &bindDN, &bindPwd, &userCont, &groupCont, &demoMode, &updatedAtStr)
	if err != nil {
		// Insert defaults if not exists
		now := time.Now().UTC()
		nowStr := now.Format(time.RFC3339)
		defaultCfg := DirectoryConfig{
			Host:               "dc01.corp.local",
			Port:               636,
			UseTLS:             true,
			InsecureSkipVerify: true,
			BaseDN:             "DC=corp,DC=local",
			BindDN:             "CN=Argus Service,OU=ServiceAccounts,DC=corp,DC=local",
			BindPassword:       "",
			UserContainer:      "OU=Users,DC=corp,DC=local",
			GroupContainer:     "OU=Groups,DC=corp,DC=local",
			DemoMode:           true, // Demo mode enabled by default
			UpdatedAt:          now,
		}

		_, _ = m.db.Exec(`
			INSERT OR REPLACE INTO directory_config (
				id, host, port, use_tls, insecure_skip_verify, base_dn, bind_dn, bind_password,
				user_container, group_container, demo_mode, updated_at
			) VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			defaultCfg.Host, defaultCfg.Port, defaultCfg.UseTLS, defaultCfg.InsecureSkipVerify,
			defaultCfg.BaseDN, defaultCfg.BindDN, defaultCfg.BindPassword,
			defaultCfg.UserContainer, defaultCfg.GroupContainer, defaultCfg.DemoMode, nowStr,
		)

		m.config = defaultCfg
	} else {
		t, _ := time.Parse(time.RFC3339, updatedAtStr)
		m.config = DirectoryConfig{
			Host:               host,
			Port:               port,
			UseTLS:             useTLS,
			InsecureSkipVerify: skipVerify,
			BaseDN:             baseDN,
			BindDN:             bindDN,
			BindPassword:       bindPwd,
			UserContainer:      userCont,
			GroupContainer:     groupCont,
			DemoMode:           demoMode,
			UpdatedAt:          t,
		}
	}

	if !m.config.DemoMode && m.config.Host != "" {
		m.ldapProvider = NewLDAPProvider(m.config)
	}

	return nil
}

func (m *Manager) activeProvider() Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config.DemoMode || m.ldapProvider == nil {
		return m.mockProvider
	}
	return m.ldapProvider
}

// GetConfig returns the configuration (masking password)
func (m *Manager) GetConfig() DirectoryConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	safeCfg := m.config
	if safeCfg.BindPassword != "" {
		safeCfg.BindPassword = "••••••••"
	}
	return safeCfg
}

// UpdateConfig updates directory connection settings
func (m *Manager) UpdateConfig(cfg DirectoryConfig, actor ActorInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Keep existing password if masked
	if cfg.BindPassword == "••••••••" || cfg.BindPassword == "" {
		cfg.BindPassword = m.config.BindPassword
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	cfg.UpdatedAt = now

	_, err := m.db.Exec(`
		UPDATE directory_config SET
			host = ?, port = ?, use_tls = ?, insecure_skip_verify = ?,
			base_dn = ?, bind_dn = ?, bind_password = ?,
			user_container = ?, group_container = ?, demo_mode = ?, updated_at = ?
		WHERE id = 'default'`,
		cfg.Host, cfg.Port, cfg.UseTLS, cfg.InsecureSkipVerify,
		cfg.BaseDN, cfg.BindDN, cfg.BindPassword,
		cfg.UserContainer, cfg.GroupContainer, cfg.DemoMode, nowStr,
	)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	oldCfgJSON, _ := json.Marshal(m.config)
	m.config = cfg

	if !cfg.DemoMode && cfg.Host != "" {
		m.ldapProvider = NewLDAPProvider(cfg)
	} else {
		m.ldapProvider = nil
	}

	safeNewCfg := cfg
	safeNewCfg.BindPassword = "••••••••"
	newCfgJSON, _ := json.Marshal(safeNewCfg)

	// Audit log
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.config.update",
		ResourceType:  "directory_config",
		ResourceID:    "default",
		Status:        "SUCCESS",
		OldValues:     string(oldCfgJSON),
		NewValues:     string(newCfgJSON),
		Reason:        "Active Directory Verbindungskonfiguration aktualisiert",
	})

	return nil
}

// TestConnection runs diagnostics
func (m *Manager) TestConnection() ConnectionTestResult {
	m.mu.RLock()
	isDemo := m.config.DemoMode
	m.mu.RUnlock()

	if isDemo {
		return m.mockProvider.TestConnection()
	}

	if m.ldapProvider != nil {
		return m.ldapProvider.TestConnection()
	}

	return ConnectionTestResult{
		Success: false,
		Message: "LDAP Provider ist nicht initialisiert (Host fehlt)",
		Latency: "0 ms",
		Demo:    false,
	}
}

// ----------------- USERS -----------------

func (m *Manager) ListUsers(search string) ([]ADUser, error) {
	return m.activeProvider().ListUsers(search)
}

func (m *Manager) GetUser(samAccountName string) (*ADUser, error) {
	return m.activeProvider().GetUser(samAccountName)
}

func (m *Manager) CreateUser(input CreateADUserInput, actor ActorInfo) (*ADUser, error) {
	user, err := m.activeProvider().CreateUser(input)
	if err != nil {
		_, _ = m.audit.Record(audit.LogEntryInput{
			ActorID:       actor.ID,
			ActorUsername: actor.Username,
			ActorIP:       actor.IPAddress,
			UserAgent:     actor.UserAgent,
			Action:        "ad.user.create",
			ResourceType:  "ad_user",
			ResourceID:    input.SAMAccountName,
			Status:        "FAILURE",
			Reason:        err.Error(),
		})
		return nil, err
	}

	userJSON, _ := json.Marshal(user)
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.user.create",
		ResourceType:  "ad_user",
		ResourceID:    user.SAMAccountName,
		Status:        "SUCCESS",
		NewValues:     string(userJSON),
		Reason:        fmt.Sprintf("AD-Benutzerkonto '%s' neu angelegt", user.SAMAccountName),
	})

	return user, nil
}

func (m *Manager) UpdateUser(samAccountName string, input UpdateADUserInput, actor ActorInfo) (*ADUser, error) {
	oldUser, _ := m.activeProvider().GetUser(samAccountName)
	var oldJSON string
	if oldUser != nil {
		b, _ := json.Marshal(oldUser)
		oldJSON = string(b)
	}

	user, err := m.activeProvider().UpdateUser(samAccountName, input)
	if err != nil {
		return nil, err
	}

	newJSON, _ := json.Marshal(user)
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.user.update",
		ResourceType:  "ad_user",
		ResourceID:    samAccountName,
		Status:        "SUCCESS",
		OldValues:     oldJSON,
		NewValues:     string(newJSON),
		Reason:        fmt.Sprintf("AD-Benutzerkonto '%s' aktualisiert", samAccountName),
	})

	return user, nil
}

func (m *Manager) SetUserStatus(samAccountName string, enabled bool, actor ActorInfo) error {
	statusStr := "aktiviert"
	if !enabled {
		statusStr = "deaktiviert"
	}

	err := m.activeProvider().SetUserStatus(samAccountName, enabled)
	if err != nil {
		return err
	}

	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.user.status",
		ResourceType:  "ad_user",
		ResourceID:    samAccountName,
		Status:        "SUCCESS",
		NewValues:     fmt.Sprintf(`{"enabled":%t}`, enabled),
		Reason:        fmt.Sprintf("AD-Konto '%s' wurde %s (UAC Flag)", samAccountName, statusStr),
	})

	return nil
}

func (m *Manager) ResetPassword(samAccountName, newPassword string, actor ActorInfo) error {
	err := m.activeProvider().ResetPassword(samAccountName, newPassword)
	if err != nil {
		_, _ = m.audit.Record(audit.LogEntryInput{
			ActorID:       actor.ID,
			ActorUsername: actor.Username,
			ActorIP:       actor.IPAddress,
			UserAgent:     actor.UserAgent,
			Action:        "ad.user.password_reset",
			ResourceType:  "ad_user",
			ResourceID:    samAccountName,
			Status:        "FAILURE",
			Reason:        err.Error(),
		})
		return err
	}

	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.user.password_reset",
		ResourceType:  "ad_user",
		ResourceID:    samAccountName,
		Status:        "SUCCESS",
		Reason:        fmt.Sprintf("Kennwort für AD-Benutzer '%s' administrativ zurückgesetzt und Konto entsperrt", samAccountName),
	})

	return nil
}

func (m *Manager) DeleteUser(samAccountName string, actor ActorInfo) error {
	err := m.activeProvider().DeleteUser(samAccountName)
	if err != nil {
		return err
	}

	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.user.delete",
		ResourceType:  "ad_user",
		ResourceID:    samAccountName,
		Status:        "SUCCESS",
		Reason:        fmt.Sprintf("AD-Benutzerkonto '%s' gelöscht", samAccountName),
	})

	return nil
}

// ----------------- GROUPS & AGDLP -----------------

func (m *Manager) ListGroups(category string) ([]ADGroup, error) {
	return m.activeProvider().ListGroups(category)
}

func (m *Manager) CreateGroup(name, description, scope string, actor ActorInfo) (*ADGroup, error) {
	grp, err := m.activeProvider().CreateGroup(name, description, scope)
	if err != nil {
		return nil, err
	}

	grpJSON, _ := json.Marshal(grp)
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.group.create",
		ResourceType:  "ad_group",
		ResourceID:    name,
		Status:        "SUCCESS",
		NewValues:     string(grpJSON),
		Reason:        fmt.Sprintf("Sicherheitsgruppe '%s' (%s) angelegt", name, scope),
	})

	return grp, nil
}

func (m *Manager) CreateAGDLPFileShare(input AGDLPShareInput, actor ActorInfo) ([]ADGroup, error) {
	groups, err := m.activeProvider().CreateAGDLPFileShare(input)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, g := range groups {
		names = append(names, g.SAMAccountName)
	}

	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.agdlp.share_create",
		ResourceType:  "file_share",
		ResourceID:    fmt.Sprintf("%s/%s", input.ShareName, input.FolderName),
		Status:        "SUCCESS",
		NewValues:     fmt.Sprintf(`{"groups":["%s"]}`, strings.Join(names, `","`)),
		Reason:        fmt.Sprintf("AGDLP Ressourcengruppen für Freigabe '%s/%s' generiert", input.ShareName, input.FolderName),
	})

	return groups, nil
}

func (m *Manager) AddMemberToGroup(groupName, member string, actor ActorInfo) error {
	err := m.activeProvider().AddMemberToGroup(groupName, member)
	if err != nil {
		return err
	}

	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.group.member_add",
		ResourceType:  "ad_group",
		ResourceID:    groupName,
		Status:        "SUCCESS",
		NewValues:     fmt.Sprintf(`{"added_member":"%s"}`, member),
		Reason:        fmt.Sprintf("Mitglied '%s' zur Gruppe '%s' hinzugefügt (AGDLP Zuweisung)", member, groupName),
	})

	return nil
}

func (m *Manager) RemoveMemberFromGroup(groupName, member string, actor ActorInfo) error {
	err := m.activeProvider().RemoveMemberFromGroup(groupName, member)
	if err != nil {
		return err
	}

	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.group.member_remove",
		ResourceType:  "ad_group",
		ResourceID:    groupName,
		Status:        "SUCCESS",
		OldValues:     fmt.Sprintf(`{"removed_member":"%s"}`, member),
		Reason:        fmt.Sprintf("Mitglied '%s' aus Gruppe '%s' entfernt", member, groupName),
	})

	return nil
}

// AGDLPMatrixFolder represents a folder with its associated permission groups
type AGDLPMatrixFolder struct {
	ShareName  string             `json:"share_name"`
	FolderName string             `json:"folder_name"`
	Groups     map[string]ADGroup `json:"groups"` // "RO" -> ADGroup, "RW" -> ADGroup, "FC" -> ADGroup
}

// GetAGDLPMatrix aggregates all file share resource groups and resolves their members
func (m *Manager) GetAGDLPMatrix() ([]AGDLPMatrixFolder, error) {
	groups, err := m.activeProvider().ListGroups("FileShare")
	if err != nil {
		return nil, err
	}

	folderMap := make(map[string]*AGDLPMatrixFolder)

	for _, g := range groups {
		if g.ShareName == "" || g.FolderName == "" {
			continue
		}
		key := fmt.Sprintf("%s/%s", strings.ToLower(g.ShareName), strings.ToLower(g.FolderName))
		folder, exists := folderMap[key]
		if !exists {
			folder = &AGDLPMatrixFolder{
				ShareName:  g.ShareName,
				FolderName: g.FolderName,
				Groups:     make(map[string]ADGroup),
			}
			folderMap[key] = folder
		}
		folder.Groups[g.Permission] = g
	}

	var result []AGDLPMatrixFolder
	for _, f := range folderMap {
		result = append(result, *f)
	}

	return result, nil
}

// CalculateEffectivePermissions resolves recursive folder access for a user
func (m *Manager) CalculateEffectivePermissions(samAccountName string) ([]EffectivePermission, error) {
	user, err := m.activeProvider().GetUser(samAccountName)
	if err != nil {
		return nil, err
	}

	userGroups := make(map[string]bool)
	for _, g := range user.MemberOf {
		userGroups[strings.ToLower(g)] = true
	}

	fsGroups, err := m.activeProvider().ListGroups("FileShare")
	if err != nil {
		return nil, err
	}

	var results []EffectivePermission

	for _, g := range fsGroups {
		if g.ShareName == "" || g.FolderName == "" {
			continue
		}

		permLabel := "Lesen"
		if g.Permission == PermReadWrite {
			permLabel = "Ändern / Schreiben"
		} else if g.Permission == PermFullControl {
			permLabel = "Vollzugriff"
		}

		// Check if user is directly a member
		for _, member := range g.Members {
			if strings.EqualFold(member, user.SAMAccountName) {
				results = append(results, EffectivePermission{
					ShareName:       g.ShareName,
					FolderName:      g.FolderName,
					Permission:      g.Permission,
					PermissionLabel: permLabel,
					InheritedVia:    "Direkt (Verletzt AGDLP)",
					ResourceGroup:   g.SAMAccountName,
				})
			} else if userGroups[strings.ToLower(member)] {
				// User is member via Global Group!
				results = append(results, EffectivePermission{
					ShareName:       g.ShareName,
					FolderName:      g.FolderName,
					Permission:      g.Permission,
					PermissionLabel: permLabel,
					InheritedVia:    member,
					ResourceGroup:   g.SAMAccountName,
				})
			}
		}
	}

	return results, nil
}

// DetectConflicts scans for AGDLP anomalies, duplicate rights, and orphaned groups
func (m *Manager) DetectConflicts() ([]PermissionConflict, error) {
	matrix, err := m.GetAGDLPMatrix()
	if err != nil {
		return nil, err
	}

	users, err := m.activeProvider().ListUsers("")
	if err != nil {
		return nil, err
	}

	var conflicts []PermissionConflict

	for _, folder := range matrix {
		// 1. Check for Orphaned Resource Groups
		for perm, grp := range folder.Groups {
			if len(grp.Members) == 0 {
				conflicts = append(conflicts, PermissionConflict{
					Type:        "ORPHANED_GROUP",
					Severity:    "INFO",
					ShareName:   folder.ShareName,
					FolderName:  folder.FolderName,
					Target:      grp.SAMAccountName,
					Description: fmt.Sprintf("Die Ressourcengruppe '%s' (%s) hat keine Mitglieder.", grp.SAMAccountName, perm),
					Suggestion:  "Weise dieser Gruppe globale Rollengruppen zu oder entferne unbenutzte Berechtigungsstufen.",
				})
			}

			// 2. Check for Direct User Assignments (violates AGDLP: A -> G -> DL -> P)
			for _, m := range grp.Members {
				if !strings.HasPrefix(m, "G_") && !strings.HasPrefix(m, "DL_") {
					conflicts = append(conflicts, PermissionConflict{
						Type:        "DIRECT_ASSIGNMENT",
						Severity:    "WARNING",
						ShareName:   folder.ShareName,
						FolderName:  folder.FolderName,
						Target:      m,
						Description: fmt.Sprintf("Benutzer '%s' ist direkt der Ressourcengruppe '%s' zugewiesen.", m, grp.SAMAccountName),
						Suggestion:  "AGDLP Best-Practice: Weise stattdessen eine globale Rollengruppe (G_*) zu und nimm den Benutzer dort auf.",
					})
				}
			}
		}
	}

	// 3. Check for Dual Access (User has both RO and RW on the same folder)
	for _, u := range users {
		perms, err := m.CalculateEffectivePermissions(u.SAMAccountName)
		if err != nil {
			continue
		}

		folderPerms := make(map[string][]string) // "Share/Folder" -> ["RO", "RW"]
		for _, p := range perms {
			key := fmt.Sprintf("%s/%s", p.ShareName, p.FolderName)
			folderPerms[key] = append(folderPerms[key], p.Permission)
		}

		for folderKey, pList := range folderPerms {
			hasRO := false
			hasRW := false
			for _, p := range pList {
				if p == PermReadOnly {
					hasRO = true
				}
				if p == PermReadWrite || p == PermFullControl {
					hasRW = true
				}
			}
			if hasRO && hasRW {
				parts := strings.Split(folderKey, "/")
				conflicts = append(conflicts, PermissionConflict{
					Type:        "DUAL_ACCESS",
					Severity:    "WARNING",
					ShareName:   parts[0],
					FolderName:  parts[1],
					Target:      u.SAMAccountName,
					Description: fmt.Sprintf("Benutzer '%s' hat redundante Rechte auf '%s' (sowohl RO als auch RW/FC).", u.SAMAccountName, folderKey),
					Suggestion:  "Entferne die Mitgliedschaft aus der Read-Only Gruppe, da Schreibrechte bereits Lesezugriff beinhalten.",
				})
			}
		}
	}

	return conflicts, nil
}

// CompareUsers provides side-by-side comparison of two identities
func (m *Manager) CompareUsers(userA, userB string) (*UserComparison, error) {
	uA, err := m.activeProvider().GetUser(userA)
	if err != nil {
		return nil, err
	}
	uB, err := m.activeProvider().GetUser(userB)
	if err != nil {
		return nil, err
	}

	permsA, err := m.CalculateEffectivePermissions(userA)
	if err != nil {
		return nil, err
	}
	permsB, err := m.CalculateEffectivePermissions(userB)
	if err != nil {
		return nil, err
	}

	groupsA := make(map[string]bool)
	for _, g := range uA.MemberOf {
		groupsA[g] = true
	}
	groupsB := make(map[string]bool)
	for _, g := range uB.MemberOf {
		groupsB[g] = true
	}

	var sharedGroups, onlyA, onlyB []string
	for g := range groupsA {
		if groupsB[g] {
			sharedGroups = append(sharedGroups, g)
		} else {
			onlyA = append(onlyA, g)
		}
	}
	for g := range groupsB {
		if !groupsA[g] {
			onlyB = append(onlyB, g)
		}
	}

	permKey := func(p EffectivePermission) string {
		return fmt.Sprintf("%s/%s/%s", p.ShareName, p.FolderName, p.Permission)
	}

	permMapA := make(map[string]EffectivePermission)
	for _, p := range permsA {
		permMapA[permKey(p)] = p
	}
	permMapB := make(map[string]EffectivePermission)
	for _, p := range permsB {
		permMapB[permKey(p)] = p
	}

	var sharedPerms, onlyPermsA, onlyPermsB []EffectivePermission
	for k, p := range permMapA {
		if _, ok := permMapB[k]; ok {
			sharedPerms = append(sharedPerms, p)
		} else {
			onlyPermsA = append(onlyPermsA, p)
		}
	}
	for k, p := range permMapB {
		if _, ok := permMapA[k]; !ok {
			onlyPermsB = append(onlyPermsB, p)
		}
	}

	return &UserComparison{
		UserA:             userA,
		UserB:             userB,
		SharedGroups:      sharedGroups,
		OnlyUserAGroups:   onlyA,
		OnlyUserBGroups:   onlyB,
		SharedPermissions: sharedPerms,
		OnlyUserAPerms:    onlyPermsA,
		OnlyUserBPerms:    onlyPermsB,
	}, nil
}

// GenerateACLScript builds production PowerShell and Bash provisioning scripts
func (m *Manager) GenerateACLScript(share, folder string) (*ACLScriptOutput, error) {
	matrix, err := m.GetAGDLPMatrix()
	if err != nil {
		return nil, err
	}

	var targetFolder *AGDLPMatrixFolder
	for _, f := range matrix {
		if strings.EqualFold(f.ShareName, share) && strings.EqualFold(f.FolderName, folder) {
			targetFolder = &f
			break
		}
	}

	groupMap := make(map[string]ADGroup)
	if targetFolder != nil {
		groupMap = targetFolder.Groups
	} else {
		// synthesize if not found yet
		ro, _ := BuildResourceGroupName(share, folder, PermReadOnly)
		rw, _ := BuildResourceGroupName(share, folder, PermReadWrite)
		fc, _ := BuildResourceGroupName(share, folder, PermFullControl)
		groupMap[PermReadOnly] = ADGroup{SAMAccountName: ro}
		groupMap[PermReadWrite] = ADGroup{SAMAccountName: rw}
		groupMap[PermFullControl] = ADGroup{SAMAccountName: fc}
	}

	out := GenerateACLACommands(share, folder, groupMap)
	return &out, nil
}
