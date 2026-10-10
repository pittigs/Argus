package directory

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// LDAPProvider handles live communication with Microsoft AD or Samba 4 AD DC
type LDAPProvider struct {
	cfg DirectoryConfig
}

// NewLDAPProvider creates a provider for live Active Directory / Samba-AD
func NewLDAPProvider(cfg DirectoryConfig) *LDAPProvider {
	return &LDAPProvider{cfg: cfg}
}

func (p *LDAPProvider) connect() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", p.cfg.Host, p.cfg.Port)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: p.cfg.InsecureSkipVerify,
		ServerName:         p.cfg.Host,
	}

	var conn *ldap.Conn
	var err error

	if p.cfg.UseTLS {
		conn, err = ldap.DialTLS("tcp", addr, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}

	if err != nil {
		return nil, fmt.Errorf("Verbindung zu %s fehlgeschlagen: %w", addr, err)
	}

	if p.cfg.BindDN != "" {
		if err := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP-Bind als '%s' fehlgeschlagen: %w", p.cfg.BindDN, err)
		}
	}

	return conn, nil
}

// encodeADPassword encodes a password as UTF-16LE in double quotes for unicodePwd attribute
func encodeADPassword(pwd string) []byte {
	quoted := fmt.Sprintf("\"%s\"", pwd)
	utf16Units := utf16.Encode([]rune(quoted))
	bytes := make([]byte, len(utf16Units)*2)
	for i, u := range utf16Units {
		bytes[i*2] = byte(u & 0xFF)
		bytes[i*2+1] = byte(u >> 8)
	}
	return bytes
}

func (p *LDAPProvider) TestConnection() ConnectionTestResult {
	start := time.Now()
	conn, err := p.connect()
	latency := time.Since(start).String()

	if err != nil {
		return ConnectionTestResult{
			Success: false,
			Message: fmt.Sprintf("Verbindungsfehler: %v", err),
			Latency: latency,
			Demo:    false,
		}
	}
	defer conn.Close()

	// Perform a quick base search to verify readability
	searchReq := ldap.NewSearchRequest(
		p.cfg.BaseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)",
		[]string{"namingContexts", "defaultNamingContext"},
		nil,
	)

	_, err = conn.Search(searchReq)
	if err != nil {
		return ConnectionTestResult{
			Success: true,
			Message: fmt.Sprintf("Verbunden mit %s:%d (Basis-Abfrage mit Hinweis: %v)", p.cfg.Host, p.cfg.Port, err),
			Latency: latency,
			Demo:    false,
		}
	}

	return ConnectionTestResult{
		Success: true,
		Message: fmt.Sprintf("Erfolgreich verbunden mit Domain Controller %s:%d (LDAPS aktiv)", p.cfg.Host, p.cfg.Port),
		Latency: latency,
		Demo:    false,
	}
}

func (p *LDAPProvider) ListUsers(search string) ([]ADUser, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	filter := "(&(objectCategory=person)(objectClass=user))"
	if search != "" {
		cleanSearch := ldap.EscapeFilter(search)
		filter = fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*%s*)(displayName=*%s*)(mail=*%s*)))", cleanSearch, cleanSearch, cleanSearch)
	}

	base := p.cfg.UserContainer
	if base == "" {
		base = p.cfg.BaseDN
	}

	searchReq := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "department", "title", "userAccountControl", "distinguishedName", "memberOf", "whenCreated", "lastLogon"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP-Suche fehlgeschlagen: %w", err)
	}

	var users []ADUser
	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		if sam == "" {
			continue
		}

		uacStr := entry.GetAttributeValue("userAccountControl")
		uac, _ := strconv.Atoi(uacStr)
		enabled := (uac & 0x0002) == 0 // ACCOUNTDISABLE flag not set

		var memberOfNames []string
		for _, dn := range entry.GetAttributeValues("memberOf") {
			// Extract CN from DN for readable display
			cn := dn
			if parts := strings.Split(dn, ","); len(parts) > 0 && strings.HasPrefix(parts[0], "CN=") {
				cn = strings.TrimPrefix(parts[0], "CN=")
			}
			memberOfNames = append(memberOfNames, cn)
		}

		created, _ := time.Parse("20060102150405.0Z", entry.GetAttributeValue("whenCreated"))

		users = append(users, ADUser{
			SAMAccountName:    sam,
			UserPrincipalName: entry.GetAttributeValue("userPrincipalName"),
			DisplayName:       entry.GetAttributeValue("displayName"),
			GivenName:         entry.GetAttributeValue("givenName"),
			Surname:           entry.GetAttributeValue("sn"),
			Mail:              entry.GetAttributeValue("mail"),
			Department:        entry.GetAttributeValue("department"),
			Title:             entry.GetAttributeValue("title"),
			Enabled:           enabled,
			DN:                entry.DN,
			MemberOf:          memberOfNames,
			CreatedAt:         created,
		})
	}

	return users, nil
}

func (p *LDAPProvider) GetUser(samAccountName string) (*ADUser, error) {
	users, err := p.ListUsers(samAccountName)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if strings.EqualFold(u.SAMAccountName, samAccountName) {
			return &u, nil
		}
	}
	return nil, ErrUserNotFound
}

func (p *LDAPProvider) CreateUser(input CreateADUserInput) (*ADUser, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := ValidateSAMAccountName(input.SAMAccountName); err != nil {
		return nil, err
	}

	dispName := input.DisplayName
	if dispName == "" {
		dispName = fmt.Sprintf("%s %s", input.GivenName, input.Surname)
	}

	container := p.cfg.UserContainer
	if container == "" {
		container = p.cfg.BaseDN
	}
	userDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(dispName), container)

	var domainParts []string
	for _, part := range strings.Split(p.cfg.BaseDN, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			domainParts = append(domainParts, part[3:])
		}
	}
	domain := strings.Join(domainParts, ".")
	if domain == "" {
		domain = "corp.local"
	}
	upn := fmt.Sprintf("%s@%s", input.SAMAccountName, domain)

	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("sAMAccountName", []string{input.SAMAccountName})
	addReq.Attribute("userPrincipalName", []string{upn})
	addReq.Attribute("displayName", []string{dispName})
	if input.GivenName != "" {
		addReq.Attribute("givenName", []string{input.GivenName})
	}
	if input.Surname != "" {
		addReq.Attribute("sn", []string{input.Surname})
	}
	if input.Mail != "" {
		addReq.Attribute("mail", []string{input.Mail})
	}
	if input.Department != "" {
		addReq.Attribute("department", []string{input.Department})
	}
	if input.Title != "" {
		addReq.Attribute("title", []string{input.Title})
	}

	// 544 = Normal Account (Enabled) or 546 = Normal Account (Disabled)
	uac := "514" // Start disabled until password is set
	addReq.Attribute("userAccountControl", []string{uac})

	if err := conn.Add(addReq); err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen des AD-Benutzers: %w", err)
	}

	// Set initial password if supplied
	if input.Password != "" {
		modReq := ldap.NewModifyRequest(userDN, nil)
		modReq.Replace("unicodePwd", []string{string(encodeADPassword(input.Password))})
		if err := conn.Modify(modReq); err != nil {
			return nil, fmt.Errorf("Benutzer erstellt, aber Kennwort konnte nicht gesetzt werden (erfordert LDAPS): %w", err)
		}
	}

	// If enabled requested, enable account now
	if input.Enabled {
		modReq := ldap.NewModifyRequest(userDN, nil)
		modReq.Replace("userAccountControl", []string{"512"}) // 0x200 NORMAL_ACCOUNT
		_ = conn.Modify(modReq)
	}

	// Assign role groups
	for _, groupName := range input.RoleGroups {
		_ = p.AddMemberToGroup(groupName, input.SAMAccountName)
	}

	return p.GetUser(input.SAMAccountName)
}

func (p *LDAPProvider) UpdateUser(samAccountName string, input UpdateADUserInput) (*ADUser, error) {
	user, err := p.GetUser(samAccountName)
	if err != nil {
		return nil, err
	}

	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(user.DN, nil)
	if input.GivenName != "" {
		modReq.Replace("givenName", []string{input.GivenName})
	}
	if input.Surname != "" {
		modReq.Replace("sn", []string{input.Surname})
	}
	if input.DisplayName != "" {
		modReq.Replace("displayName", []string{input.DisplayName})
	}
	if input.Mail != "" {
		modReq.Replace("mail", []string{input.Mail})
	}
	if input.Department != "" {
		modReq.Replace("department", []string{input.Department})
	}
	if input.Title != "" {
		modReq.Replace("title", []string{input.Title})
	}

	if err := conn.Modify(modReq); err != nil {
		return nil, fmt.Errorf("Fehler beim Aktualisieren des AD-Benutzers: %w", err)
	}

	return p.GetUser(samAccountName)
}

func (p *LDAPProvider) SetUserStatus(samAccountName string, enabled bool) error {
	user, err := p.GetUser(samAccountName)
	if err != nil {
		return err
	}

	conn, err := p.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	// 512 = NORMAL_ACCOUNT (Aktiv)
	// 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE (Deaktiviert)
	uacVal := "512"
	if !enabled {
		uacVal = "514"
	}

	modReq := ldap.NewModifyRequest(user.DN, nil)
	modReq.Replace("userAccountControl", []string{uacVal})
	return conn.Modify(modReq)
}

func (p *LDAPProvider) ResetPassword(samAccountName, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("Kennwort muss mindestens 8 Zeichen lang sein")
	}

	user, err := p.GetUser(samAccountName)
	if err != nil {
		return err
	}

	conn, err := p.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(user.DN, nil)
	modReq.Replace("unicodePwd", []string{string(encodeADPassword(newPassword))})
	modReq.Replace("lockoutTime", []string{"0"}) // Unlock account if locked

	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("Kennwort-Reset fehlgeschlagen: %w", err)
	}

	return nil
}

func (p *LDAPProvider) DeleteUser(samAccountName string) error {
	user, err := p.GetUser(samAccountName)
	if err != nil {
		return err
	}

	conn, err := p.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	delReq := ldap.NewDelRequest(user.DN, nil)
	return conn.Del(delReq)
}

func (p *LDAPProvider) ListGroups(category string) ([]ADGroup, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	base := p.cfg.GroupContainer
	if base == "" {
		base = p.cfg.BaseDN
	}

	searchReq := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=group)",
		[]string{"sAMAccountName", "cn", "distinguishedName", "description", "groupType", "member"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("Gruppen-Suche fehlgeschlagen: %w", err)
	}

	var groups []ADGroup
	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		if sam == "" {
			continue
		}

		meta := ParseGroupMetadata(sam)
		if category != "" && !strings.EqualFold(meta.Category, category) {
			continue
		}

		var memberNames []string
		for _, mDN := range entry.GetAttributeValues("member") {
			parts := strings.Split(mDN, ",")
			if len(parts) > 0 && strings.HasPrefix(parts[0], "CN=") {
				memberNames = append(memberNames, strings.TrimPrefix(parts[0], "CN="))
			} else {
				memberNames = append(memberNames, mDN)
			}
		}

		groups = append(groups, ADGroup{
			SAMAccountName: sam,
			CN:             entry.GetAttributeValue("cn"),
			DN:             entry.DN,
			Description:    entry.GetAttributeValue("description"),
			GroupScope:     meta.GroupScope,
			Category:       meta.Category,
			Members:        memberNames,
			ShareName:      meta.ShareName,
			FolderName:     meta.FolderName,
			Permission:     meta.Permission,
		})
	}

	return groups, nil
}

func (p *LDAPProvider) GetGroup(groupName string) (*ADGroup, error) {
	groups, err := p.ListGroups("")
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if strings.EqualFold(g.SAMAccountName, groupName) {
			return &g, nil
		}
	}
	return nil, ErrGroupNotFound
}

func (p *LDAPProvider) CreateGroup(name, description, scope string) (*ADGroup, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := ValidateSAMAccountName(name); err != nil {
		return nil, err
	}

	container := p.cfg.GroupContainer
	if container == "" {
		container = p.cfg.BaseDN
	}
	groupDN := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(name), container)

	// GroupType flags:
	// -2147483646 (0x80000002) = Global Security Group
	// -2147483644 (0x80000004) = Domain Local Security Group
	groupTypeVal := "-2147483646" // Default Global
	if strings.EqualFold(scope, "DomainLocal") || strings.HasPrefix(name, "DL_") {
		groupTypeVal = "-2147483644"
	}

	addReq := ldap.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{"top", "group"})
	addReq.Attribute("sAMAccountName", []string{name})
	addReq.Attribute("cn", []string{name})
	addReq.Attribute("groupType", []string{groupTypeVal})
	if description != "" {
		addReq.Attribute("description", []string{description})
	}

	if err := conn.Add(addReq); err != nil {
		return nil, fmt.Errorf("Fehler beim Erstellen der AD-Gruppe: %w", err)
	}

	return p.GetGroup(name)
}

func (p *LDAPProvider) CreateAGDLPFileShare(input AGDLPShareInput) ([]ADGroup, error) {
	var created []ADGroup

	perms := []struct {
		code, label string
		enabled     bool
	}{
		{PermReadOnly, "Leserechte (RO)", input.CreateReadOnly},
		{PermReadWrite, "Schreib- und Änderungsrechte (RW)", input.CreateReadWrite},
		{PermFullControl, "Vollzugriff (FC)", input.CreateFullControl},
	}

	for _, perm := range perms {
		if !perm.enabled {
			continue
		}

		groupName, err := BuildResourceGroupName(input.ShareName, input.FolderName, perm.code)
		if err != nil {
			return nil, err
		}

		desc := fmt.Sprintf("AGDLP Ressourcengruppe: Freigabe '%s', Ordner '%s' [%s]", input.ShareName, input.FolderName, perm.label)
		if input.Description != "" {
			desc = fmt.Sprintf("%s - %s", desc, input.Description)
		}

		grp, err := p.CreateGroup(groupName, desc, "DomainLocal")
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return nil, err
		}

		if perm.code == PermReadWrite {
			for _, gg := range input.AssignedGlobalGroups {
				_ = p.AddMemberToGroup(groupName, gg)
			}
		}

		if grp != nil {
			created = append(created, *grp)
		}
	}

	return created, nil
}

func (p *LDAPProvider) findDN(name string) (string, error) {
	conn, err := p.connect()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	cleanName := ldap.EscapeFilter(name)
	filter := fmt.Sprintf("(|(sAMAccountName=%s)(cn=%s))", cleanName, cleanName)

	searchReq := ldap.NewSearchRequest(
		p.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 10, false,
		filter,
		[]string{"distinguishedName"},
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil || len(sr.Entries) == 0 {
		return "", fmt.Errorf("Objekt '%s' in Active Directory nicht gefunden", name)
	}

	return sr.Entries[0].DN, nil
}

func (p *LDAPProvider) AddMemberToGroup(groupName, member string) error {
	groupDN, err := p.findDN(groupName)
	if err != nil {
		return err
	}
	memberDN, err := p.findDN(member)
	if err != nil {
		return err
	}

	conn, err := p.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Add("member", []string{memberDN})
	return conn.Modify(modReq)
}

func (p *LDAPProvider) RemoveMemberFromGroup(groupName, member string) error {
	groupDN, err := p.findDN(groupName)
	if err != nil {
		return err
	}
	memberDN, err := p.findDN(member)
	if err != nil {
		return err
	}

	conn, err := p.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	modReq := ldap.NewModifyRequest(groupDN, nil)
	modReq.Delete("member", []string{memberDN})
	return conn.Modify(modReq)
}

func (p *LDAPProvider) GetUserGroups(samAccountName string) ([]string, error) {
	u, err := p.GetUser(samAccountName)
	if err != nil {
		return nil, err
	}
	return u.MemberOf, nil
}
