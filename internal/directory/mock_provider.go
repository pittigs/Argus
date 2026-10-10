package directory

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// MockProvider provides an in-memory Active Directory / Samba-AD environment
type MockProvider struct {
	mu     sync.RWMutex
	users  map[string]ADUser
	groups map[string]ADGroup
}

// NewMockProvider initializes the mock with realistic enterprise AD objects
func NewMockProvider() *MockProvider {
	mp := &MockProvider{
		users:  make(map[string]ADUser),
		groups: make(map[string]ADGroup),
	}
	mp.seed()
	return mp
}

func (m *MockProvider) seed() {
	now := time.Now().UTC()
	t1 := now.Add(-2 * time.Hour)
	t2 := now.Add(-24 * time.Hour)
	t3 := now.Add(-5 * 24 * time.Hour)

	// 1. Seed Groups
	initialGroups := []struct {
		name, desc, scope string
	}{
		{"G_DEV_Argus", "Argus Kern-Softwareentwicklungsteam", "Global"},
		{"G_IT_Security", "Konzernweite Informationssicherheit & IT-Audit", "Global"},
		{"G_HR_Mitarbeiter", "Personalabteilung & Talent Management", "Global"},
		{"G_FIN_Buchhaltung", "Finanzbuchhaltung & Controlling", "Global"},
		{"DL_FS_Projekte_Argus_RO", "Dateifreigabe Projekte/Argus - Leserechte", "DomainLocal"},
		{"DL_FS_Projekte_Argus_RW", "Dateifreigabe Projekte/Argus - Schreib- und Änderungsrechte", "DomainLocal"},
		{"DL_FS_Finanzen_2026_RW", "Dateifreigabe Finanzen/2026 - Buchhaltungszugriff", "DomainLocal"},
		{"DL_FS_Personal_Vertraege_RO", "Dateifreigabe Personal/Vertraege - Lesezugriff", "DomainLocal"},
		{"DL_FS_Personal_Vertraege_FC", "Dateifreigabe Personal/Vertraege - Vollzugriff Leitung", "DomainLocal"},
	}

	for _, g := range initialGroups {
		meta := ParseGroupMetadata(g.name)
		m.groups[strings.ToLower(g.name)] = ADGroup{
			SAMAccountName: g.name,
			CN:             g.name,
			DN:             fmt.Sprintf("CN=%s,OU=Groups,DC=corp,DC=local", g.name),
			Description:    g.desc,
			GroupScope:     g.scope,
			Category:       meta.Category,
			Members:        []string{},
			ShareName:      meta.ShareName,
			FolderName:     meta.FolderName,
			Permission:     meta.Permission,
		}
	}

	// 2. Link Global Groups into Domain Local Groups (AGDLP: G -> DL)
	m.addMemberInternal("DL_FS_Projekte_Argus_RW", "G_DEV_Argus")
	m.addMemberInternal("DL_FS_Projekte_Argus_RO", "G_IT_Security")
	m.addMemberInternal("DL_FS_Finanzen_2026_RW", "G_FIN_Buchhaltung")
	m.addMemberInternal("DL_FS_Personal_Vertraege_RO", "G_HR_Mitarbeiter")
	m.addMemberInternal("DL_FS_Personal_Vertraege_FC", "G_IT_Security")

	// 3. Seed Users (AGDLP: A -> G)
	initialUsers := []struct {
		sam, first, last, mail, dept, title string
		enabled                              bool
		lastLogon                            *time.Time
		roleGroups                           []string
	}{
		{
			sam: "sarah.connor", first: "Sarah", last: "Connor",
			mail: "s.connor@corp.local", dept: "Software Engineering", title: "Lead IAM Architect",
			enabled: true, lastLogon: &t1,
			roleGroups: []string{"G_DEV_Argus"},
		},
		{
			sam: "max.mustermann", first: "Max", last: "Mustermann",
			mail: "m.mustermann@corp.local", dept: "IT-Security", title: "CISO / Security Lead",
			enabled: true, lastLogon: &t2,
			roleGroups: []string{"G_IT_Security"},
		},
		{
			sam: "johann.schmidt", first: "Johann", last: "Schmidt",
			mail: "j.schmidt@corp.local", dept: "Human Resources", title: "Senior HR Officer",
			enabled: true, lastLogon: &t3,
			roleGroups: []string{"G_HR_Mitarbeiter"},
		},
		{
			sam: "elena.rostova", first: "Elena", last: "Rostova",
			mail: "e.rostova@corp.local", dept: "Finance", title: "Head of Accounting",
			enabled: true, lastLogon: &t1,
			roleGroups: []string{"G_FIN_Buchhaltung"},
		},
		{
			sam: "service.backup", first: "Svc", last: "Backup",
			mail: "svc.backup@corp.local", dept: "IT Infrastructure", title: "Backup Automation Service Account",
			enabled: false, lastLogon: nil,
			roleGroups: []string{},
		},
	}

	for _, u := range initialUsers {
		key := strings.ToLower(u.sam)
		m.users[key] = ADUser{
			SAMAccountName:    u.sam,
			UserPrincipalName: fmt.Sprintf("%s@corp.local", u.sam),
			DisplayName:       fmt.Sprintf("%s %s", u.first, u.last),
			GivenName:         u.first,
			Surname:           u.last,
			Mail:              u.mail,
			Department:        u.dept,
			Title:             u.title,
			Enabled:           u.enabled,
			DN:                fmt.Sprintf("CN=%s %s,OU=Users,DC=corp,DC=local", u.first, u.last),
			MemberOf:          u.roleGroups,
			CreatedAt:         now.Add(-30 * 24 * time.Hour),
			LastLogon:         u.lastLogon,
		}

		for _, rg := range u.roleGroups {
			m.addMemberInternal(rg, u.sam)
		}
	}
}

func (m *MockProvider) addMemberInternal(groupName, member string) {
	key := strings.ToLower(groupName)
	if grp, ok := m.groups[key]; ok {
		for _, existing := range grp.Members {
			if strings.EqualFold(existing, member) {
				return
			}
		}
		grp.Members = append(grp.Members, member)
		m.groups[key] = grp
	}
}

func (m *MockProvider) TestConnection() ConnectionTestResult {
	return ConnectionTestResult{
		Success: true,
		Message: "Samba-AD / Windows-AD Mock-Provider aktiv (Simulierte Active Directory Umgebung)",
		Latency: "1.2 ms",
		Demo:    true,
	}
}

func (m *MockProvider) ListUsers(search string) ([]ADUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	search = strings.ToLower(strings.TrimSpace(search))
	var result []ADUser

	for _, u := range m.users {
		if search != "" {
			if !strings.Contains(strings.ToLower(u.SAMAccountName), search) &&
				!strings.Contains(strings.ToLower(u.DisplayName), search) &&
				!strings.Contains(strings.ToLower(u.Mail), search) &&
				!strings.Contains(strings.ToLower(u.Department), search) {
				continue
			}
		}
		result = append(result, u)
	}

	return result, nil
}

func (m *MockProvider) GetUser(samAccountName string) (*ADUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.users[strings.ToLower(samAccountName)]
	if !ok {
		return nil, ErrUserNotFound
	}
	return &u, nil
}

func (m *MockProvider) CreateUser(input CreateADUserInput) (*ADUser, error) {
	if err := ValidateSAMAccountName(input.SAMAccountName); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(input.SAMAccountName)
	if _, ok := m.users[key]; ok {
		return nil, ErrUserExists
	}

	dispName := input.DisplayName
	if dispName == "" {
		dispName = fmt.Sprintf("%s %s", input.GivenName, input.Surname)
	}

	user := ADUser{
		SAMAccountName:    input.SAMAccountName,
		UserPrincipalName: fmt.Sprintf("%s@corp.local", input.SAMAccountName),
		DisplayName:       dispName,
		GivenName:         input.GivenName,
		Surname:           input.Surname,
		Mail:              input.Mail,
		Department:        input.Department,
		Title:             input.Title,
		Enabled:           input.Enabled,
		DN:                fmt.Sprintf("CN=%s,OU=Users,DC=corp,DC=local", dispName),
		MemberOf:          input.RoleGroups,
		CreatedAt:         time.Now().UTC(),
	}

	m.users[key] = user

	// Add to assigned groups
	for _, rg := range input.RoleGroups {
		m.addMemberInternal(rg, input.SAMAccountName)
	}

	return &user, nil
}

func (m *MockProvider) UpdateUser(samAccountName string, input UpdateADUserInput) (*ADUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(samAccountName)
	u, ok := m.users[key]
	if !ok {
		return nil, ErrUserNotFound
	}

	if input.GivenName != "" {
		u.GivenName = input.GivenName
	}
	if input.Surname != "" {
		u.Surname = input.Surname
	}
	if input.DisplayName != "" {
		u.DisplayName = input.DisplayName
	} else if input.GivenName != "" || input.Surname != "" {
		u.DisplayName = fmt.Sprintf("%s %s", u.GivenName, u.Surname)
	}
	if input.Mail != "" {
		u.Mail = input.Mail
	}
	if input.Department != "" {
		u.Department = input.Department
	}
	if input.Title != "" {
		u.Title = input.Title
	}

	m.users[key] = u
	return &u, nil
}

func (m *MockProvider) SetUserStatus(samAccountName string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(samAccountName)
	u, ok := m.users[key]
	if !ok {
		return ErrUserNotFound
	}

	u.Enabled = enabled
	m.users[key] = u
	return nil
}

func (m *MockProvider) ResetPassword(samAccountName, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("Kennwort muss mindestens 8 Zeichen lang sein")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key := strings.ToLower(samAccountName)
	if _, ok := m.users[key]; !ok {
		return ErrUserNotFound
	}

	return nil
}

func (m *MockProvider) DeleteUser(samAccountName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(samAccountName)
	if _, ok := m.users[key]; !ok {
		return ErrUserNotFound
	}

	delete(m.users, key)

	// Remove from all group memberships
	for gKey, grp := range m.groups {
		var newMembers []string
		for _, member := range grp.Members {
			if !strings.EqualFold(member, samAccountName) {
				newMembers = append(newMembers, member)
			}
		}
		grp.Members = newMembers
		m.groups[gKey] = grp
	}

	return nil
}

func (m *MockProvider) ListGroups(category string) ([]ADGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	category = strings.ToLower(strings.TrimSpace(category))
	var result []ADGroup

	for _, g := range m.groups {
		if category != "" && strings.ToLower(g.Category) != category {
			continue
		}
		result = append(result, g)
	}

	return result, nil
}

func (m *MockProvider) GetGroup(groupName string) (*ADGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	g, ok := m.groups[strings.ToLower(groupName)]
	if !ok {
		return nil, ErrGroupNotFound
	}
	return &g, nil
}

func (m *MockProvider) CreateGroup(name, description, scope string) (*ADGroup, error) {
	if err := ValidateSAMAccountName(name); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(name)
	if _, ok := m.groups[key]; ok {
		return nil, ErrGroupExists
	}

	meta := ParseGroupMetadata(name)
	if scope == "" {
		scope = meta.GroupScope
	}

	group := ADGroup{
		SAMAccountName: name,
		CN:             name,
		DN:             fmt.Sprintf("CN=%s,OU=Groups,DC=corp,DC=local", name),
		Description:    description,
		GroupScope:     scope,
		Category:       meta.Category,
		Members:        []string{},
		ShareName:      meta.ShareName,
		FolderName:     meta.FolderName,
		Permission:     meta.Permission,
	}

	m.groups[key] = group
	return &group, nil
}

func (m *MockProvider) CreateAGDLPFileShare(input AGDLPShareInput) ([]ADGroup, error) {
	if input.ShareName == "" || input.FolderName == "" {
		return nil, fmt.Errorf("Freigabe und Ordnername müssen angegeben werden")
	}

	var created []ADGroup

	// Permissions to generate
	perms := []struct {
		code, label string
		enabled     bool
	}{
		{PermReadOnly, "Leserechte (RO)", input.CreateReadOnly},
		{PermReadWrite, "Schreib- und Änderungsrechte (RW)", input.CreateReadWrite},
		{PermFullControl, "Vollzugriff (FC)", input.CreateFullControl},
	}

	for _, p := range perms {
		if !p.enabled {
			continue
		}

		groupName, err := BuildResourceGroupName(input.ShareName, input.FolderName, p.code)
		if err != nil {
			return nil, err
		}

		desc := fmt.Sprintf("AGDLP Ressourcengruppe: Freigabe '%s', Ordner '%s' [%s]", input.ShareName, input.FolderName, p.label)
		if input.Description != "" {
			desc = fmt.Sprintf("%s - %s", desc, input.Description)
		}

		grp, err := m.CreateGroup(groupName, desc, "DomainLocal")
		if err != nil && err != ErrGroupExists {
			return nil, err
		}
		if grp == nil {
			// group existed, fetch it
			grp, _ = m.GetGroup(groupName)
		}

		// Assign global groups if RW and specified
		if p.code == PermReadWrite {
			for _, gg := range input.AssignedGlobalGroups {
				_ = m.AddMemberToGroup(groupName, gg)
			}
		}

		if grp != nil {
			// refetch updated
			refreshed, _ := m.GetGroup(grp.SAMAccountName)
			if refreshed != nil {
				created = append(created, *refreshed)
			}
		}
	}

	return created, nil
}

func (m *MockProvider) AddMemberToGroup(groupName, member string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	gKey := strings.ToLower(groupName)
	grp, ok := m.groups[gKey]
	if !ok {
		return ErrGroupNotFound
	}

	for _, existing := range grp.Members {
		if strings.EqualFold(existing, member) {
			return nil // already member
		}
	}

	grp.Members = append(grp.Members, member)
	m.groups[gKey] = grp

	// If member is a user, also update user's memberOf list
	uKey := strings.ToLower(member)
	if u, exists := m.users[uKey]; exists {
		found := false
		for _, g := range u.MemberOf {
			if strings.EqualFold(g, groupName) {
				found = true
				break
			}
		}
		if !found {
			u.MemberOf = append(u.MemberOf, groupName)
			m.users[uKey] = u
		}
	}

	return nil
}

func (m *MockProvider) RemoveMemberFromGroup(groupName, member string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	gKey := strings.ToLower(groupName)
	grp, ok := m.groups[gKey]
	if !ok {
		return ErrGroupNotFound
	}

	var newMembers []string
	for _, m := range grp.Members {
		if !strings.EqualFold(m, member) {
			newMembers = append(newMembers, m)
		}
	}
	grp.Members = newMembers
	m.groups[gKey] = grp

	// Update user's memberOf if it was a user
	uKey := strings.ToLower(member)
	if u, exists := m.users[uKey]; exists {
		var newMemberOf []string
		for _, g := range u.MemberOf {
			if !strings.EqualFold(g, groupName) {
				newMemberOf = append(newMemberOf, g)
			}
		}
		u.MemberOf = newMemberOf
		m.users[uKey] = u
	}

	return nil
}

func (m *MockProvider) GetUserGroups(samAccountName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.users[strings.ToLower(samAccountName)]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u.MemberOf, nil
}
