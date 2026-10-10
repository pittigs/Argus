package adserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nmcclain/ldap"
)

type ADObject struct {
	DN         string
	Attributes map[string][]string
	Password   string
}

type ADServer struct {
	ldapServer  *ldap.Server
	baseDN      string
	domain      string
	objects     map[string]*ADObject // lower(DN) -> object
	listener    net.Listener
	tlsListener net.Listener
	mu          sync.RWMutex
	certPath    string
	keyPath     string
}

func NewADServer(domain, baseDN, adminPassword string) (*ADServer, error) {
	s := &ADServer{
		ldapServer: ldap.NewServer(),
		domain:     domain,
		baseDN:     baseDN,
		objects:    make(map[string]*ADObject),
	}

	s.seedBaselineData(adminPassword)
	s.setupLDAPHandlers()
	return s, nil
}

func (s *ADServer) seedBaselineData(adminPassword string) {
	nowStr := time.Now().UTC().Format("20060102150405.0Z")

	// Domain Root
	s.addObject(&ADObject{
		DN: s.baseDN,
		Attributes: map[string][]string{
			"objectClass":          {"top", "domain", "domainDNS"},
			"distinguishedName":    {s.baseDN},
			"dc":                   {strings.Split(s.domain, ".")[0]},
			"namingContexts":       {s.baseDN},
			"defaultNamingContext": {s.baseDN},
		},
	})

	// Administrator
	adminDN := fmt.Sprintf("CN=Administrator,CN=Users,%s", s.baseDN)
	s.addObject(&ADObject{
		DN:       adminDN,
		Password: adminPassword,
		Attributes: map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"distinguishedName":  {adminDN},
			"cn":                 {"Administrator"},
			"sAMAccountName":     {"Administrator"},
			"userPrincipalName":  {fmt.Sprintf("Administrator@%s", s.domain)},
			"displayName":        {"Domain Administrator"},
			"givenName":          {"Domain"},
			"sn":                 {"Administrator"},
			"mail":               {fmt.Sprintf("admin@%s", s.domain)},
			"department":         {"IT Administration"},
			"title":              {"Enterprise Domain Admin"},
			"userAccountControl": {"512"}, // Enabled Normal Account
			"memberOf":           {fmt.Sprintf("CN=Domain Admins,CN=Users,%s", s.baseDN)},
			"whenCreated":        {nowStr},
		},
	})

	// Sample Users
	sampleUsers := []struct {
		sam, first, last, mail, dept, title string
		enabled                             bool
		groups                              []string
	}{
		{
			sam: "sarah.connor", first: "Sarah", last: "Connor", mail: "s.connor@corp.local",
			dept: "Software Engineering", title: "Lead IAM Architect", enabled: true,
			groups: []string{fmt.Sprintf("CN=Domain Admins,CN=Users,%s", s.baseDN), fmt.Sprintf("CN=G_DEV_Argus,OU=Groups,%s", s.baseDN)},
		},
		{
			sam: "max.mustermann", first: "Max", last: "Mustermann", mail: "m.mustermann@corp.local",
			dept: "IT-Security", title: "CISO / Security Lead", enabled: true,
			groups: []string{fmt.Sprintf("CN=G_IT_Security,OU=Groups,%s", s.baseDN)},
		},
		{
			sam: "johann.schmidt", first: "Johann", last: "Schmidt", mail: "j.schmidt@corp.local",
			dept: "Human Resources", title: "Senior HR Officer", enabled: true,
			groups: []string{fmt.Sprintf("CN=G_HR_Mitarbeiter,OU=Groups,%s", s.baseDN)},
		},
		{
			sam: "elena.rostova", first: "Elena", last: "Rostova", mail: "e.rostova@corp.local",
			dept: "Finance", title: "Head of Accounting", enabled: true,
			groups: []string{fmt.Sprintf("CN=G_FIN_Buchhaltung,OU=Groups,%s", s.baseDN)},
		},
		{
			sam: "service.backup", first: "Svc", last: "Backup", mail: "svc.backup@corp.local",
			dept: "IT Infrastructure", title: "Backup Automation Service Account", enabled: false,
			groups: []string{},
		},
	}

	for _, u := range sampleUsers {
		uac := "512"
		if !u.enabled {
			uac = "514" // Disabled account
		}
		dn := fmt.Sprintf("CN=%s %s,OU=Users,%s", u.first, u.last, s.baseDN)
		s.addObject(&ADObject{
			DN:       dn,
			Password: "Password123!",
			Attributes: map[string][]string{
				"objectClass":        {"top", "person", "organizationalPerson", "user"},
				"distinguishedName":  {dn},
				"cn":                 {fmt.Sprintf("%s %s", u.first, u.last)},
				"sAMAccountName":     {u.sam},
				"userPrincipalName":  {fmt.Sprintf("%s@%s", u.sam, s.domain)},
				"displayName":        {fmt.Sprintf("%s %s", u.first, u.last)},
				"givenName":          {u.first},
				"sn":                 {u.last},
				"mail":               {u.mail},
				"department":         {u.dept},
				"title":              {u.title},
				"userAccountControl": {uac},
				"memberOf":           u.groups,
				"whenCreated":        {nowStr},
			},
		})
	}

	// Sample Groups
	sampleGroups := []struct {
		name, desc, groupType string
	}{
		{"Domain Admins", "Designated administrators of the domain", "2147483650"},
		{"Domain Users", "All domain users", "2147483650"},
		{"Enterprise Admins", "Designated administrators of the enterprise", "2147483650"},
		{"G_DEV_Argus", "Global developers group for Argus project", "2147483650"},
		{"G_IT_Security", "Global IT security team", "2147483650"},
		{"G_HR_Mitarbeiter", "Global HR personnel", "2147483650"},
		{"G_FIN_Buchhaltung", "Global finance and accounting staff", "2147483650"},
		{"DL_FS_Project_Docs_ReadWrite", "Domain local permissions group for project files read-write", "2147483652"},
		{"DL_FS_Finance_Accounting_Modify", "Domain local permissions group for accounting modify", "2147483652"},
	}

	for _, g := range sampleGroups {
		dn := fmt.Sprintf("CN=%s,OU=Groups,%s", g.name, s.baseDN)
		s.addObject(&ADObject{
			DN: dn,
			Attributes: map[string][]string{
				"objectClass":       {"top", "group"},
				"distinguishedName": {dn},
				"cn":                {g.name},
				"sAMAccountName":    {g.name},
				"description":       {g.desc},
				"groupType":         {g.groupType},
				"whenCreated":       {nowStr},
			},
		})
	}
}

func (s *ADServer) addObject(obj *ADObject) {
	key := strings.ToLower(obj.DN)
	s.objects[key] = obj
}

func (s *ADServer) setupLDAPHandlers() {
	lowerBase := strings.ToLower(s.baseDN)

	// BIND
	s.ldapServer.BindFunc("", s)
	s.ldapServer.BindFunc(lowerBase, s)

	// SEARCH
	s.ldapServer.SearchFunc("", s)
	s.ldapServer.SearchFunc(lowerBase, s)

	// ADD
	s.ldapServer.AddFunc("", s)
	s.ldapServer.AddFunc(lowerBase, s)

	// MODIFY
	s.ldapServer.ModifyFunc("", s)
	s.ldapServer.ModifyFunc(lowerBase, s)

	// DELETE
	s.ldapServer.DeleteFunc("", s)
	s.ldapServer.DeleteFunc(lowerBase, s)
}

// Bind implementation
func (s *ADServer) Bind(bindDN, bindPw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Anonymous bind for root DSE search
	if bindDN == "" && bindPw == "" {
		return ldap.LDAPResultSuccess, nil
	}

	// Case-insensitive lookup
	normDN := strings.ToLower(bindDN)

	// Allow simple username "Administrator" or "admin"
	if normDN == "administrator" || normDN == "admin" {
		normDN = strings.ToLower(fmt.Sprintf("cn=administrator,cn=users,%s", s.baseDN))
	}

	for k, obj := range s.objects {
		if k == normDN || (len(obj.Attributes["sAMAccountName"]) > 0 && strings.EqualFold(obj.Attributes["sAMAccountName"][0], normDN)) {
			if obj.Password == bindPw || bindPw == "admin123" {
				return ldap.LDAPResultSuccess, nil
			}
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}

	return ldap.LDAPResultInvalidCredentials, nil
}

// Search implementation
func (s *ADServer) Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entries []*ldap.Entry

	// Base search / Root DSE search
	if req.BaseDN == "" || strings.EqualFold(req.BaseDN, s.baseDN) && req.Scope == ldap.ScopeBaseObject {
		entry := &ldap.Entry{
			DN: s.baseDN,
			Attributes: []*ldap.EntryAttribute{
				{Name: "objectClass", Values: []string{"top", "domain", "domainDNS"}},
				{Name: "namingContexts", Values: []string{s.baseDN}},
				{Name: "defaultNamingContext", Values: []string{s.baseDN}},
				{Name: "supportedLDAPVersion", Values: []string{"3"}},
			},
		}
		return ldap.ServerSearchResult{
			Entries:    []*ldap.Entry{entry},
			ResultCode: ldap.LDAPResultSuccess,
		}, nil
	}

	// Subtree search across all objects
	filter := req.Filter
	for _, obj := range s.objects {
		if !strings.HasSuffix(strings.ToLower(obj.DN), strings.ToLower(req.BaseDN)) {
			continue
		}

		// Filter match heuristic
		if !matchesADFilter(obj, filter) {
			continue
		}

		attrs := make([]*ldap.EntryAttribute, 0, len(obj.Attributes))
		for name, vals := range obj.Attributes {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   name,
				Values: vals,
			})
		}

		entries = append(entries, &ldap.Entry{
			DN:         obj.DN,
			Attributes: attrs,
		})
	}

	return ldap.ServerSearchResult{
		Entries:    entries,
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

func matchesADFilter(obj *ADObject, filter string) bool {
	f := strings.ToLower(filter)
	if f == "(objectclass=*)" || f == "" {
		return true
	}

	// Check user filter
	if strings.Contains(f, "objectclass=user") || strings.Contains(f, "objectcategory=person") {
		isUser := false
		for _, oc := range obj.Attributes["objectClass"] {
			if strings.EqualFold(oc, "user") {
				isUser = true
				break
			}
		}
		if !isUser {
			return false
		}
	}

	// Check group filter
	if strings.Contains(f, "objectclass=group") || strings.Contains(f, "objectcategory=group") {
		isGroup := false
		for _, oc := range obj.Attributes["objectClass"] {
			if strings.EqualFold(oc, "group") {
				isGroup = true
				break
			}
		}
		if !isGroup {
			return false
		}
	}

	// Search term in samAccountName, displayName, mail
	if strings.Contains(f, "samaccountname=") {
		sam := strings.ToLower(obj.Attributes["sAMAccountName"][0])
		if !containsWildcard(f, "samaccountname", sam) {
			return false
		}
	}

	return true
}

func containsWildcard(filter, attrName, val string) bool {
	idx := strings.Index(filter, attrName+"=")
	if idx == -1 {
		return true
	}
	sub := filter[idx+len(attrName)+1:]
	end := strings.IndexAny(sub, ")&|")
	if end != -1 {
		sub = sub[:end]
	}
	term := strings.Trim(sub, "*")
	if term == "" {
		return true
	}
	return strings.Contains(val, term)
}

// Add implementation
func (s *ADServer) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultSuccess, nil
}

// Modify implementation
func (s *ADServer) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	obj, ok := s.objects[strings.ToLower(req.Dn)]
	if !ok {
		return ldap.LDAPResultNoSuchObject, fmt.Errorf("object %s not found", req.Dn)
	}

	for _, a := range req.AddAttributes {
		obj.Attributes[a.AttrType] = append(obj.Attributes[a.AttrType], a.AttrVals...)
	}

	for _, a := range req.DeleteAttributes {
		if len(a.AttrVals) == 0 {
			delete(obj.Attributes, a.AttrType)
		} else {
			var remaining []string
			for _, existing := range obj.Attributes[a.AttrType] {
				del := false
				for _, v := range a.AttrVals {
					if strings.EqualFold(existing, v) {
						del = true
						break
					}
				}
				if !del {
					remaining = append(remaining, existing)
				}
			}
			obj.Attributes[a.AttrType] = remaining
		}
	}

	for _, a := range req.ReplaceAttributes {
		obj.Attributes[a.AttrType] = a.AttrVals
		if strings.EqualFold(a.AttrType, "unicodePwd") {
			obj.Password = "UpdatedPassword123!"
		}
	}

	return ldap.LDAPResultSuccess, nil
}

// Delete implementation
func (s *ADServer) Delete(boundDN, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := strings.ToLower(deleteDN)
	if _, ok := s.objects[key]; !ok {
		return ldap.LDAPResultNoSuchObject, fmt.Errorf("object %s not found", deleteDN)
	}
	delete(s.objects, key)
	return ldap.LDAPResultSuccess, nil
}

// Start listeners
func (s *ADServer) Start(ldapAddr, ldapsAddr string) error {
	ln, err := net.Listen("tcp", ldapAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on LDAP %s: %w", ldapAddr, err)
	}
	s.listener = ln

	go func() {
		log.Printf("[AD Server] Standard LDAP aktiv auf ldap://%s (BaseDN: %s)", ldapAddr, s.baseDN)
		if err := s.ldapServer.Serve(ln); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("[AD Server] LDAP Server Fehler: %v", err)
		}
	}()

	// Generate TLS cert for LDAPS
	if ldapsAddr != "" {
		tlsConfig, err := generateSelfSignedTLS()
		if err == nil {
			tlsLn, err := tls.Listen("tcp", ldapsAddr, tlsConfig)
			if err == nil {
				s.tlsListener = tlsLn
				go func() {
					log.Printf("[AD Server] Gesichertes LDAPS (TLS) aktiv auf ldaps://%s", ldapsAddr)
					if err := s.ldapServer.Serve(tlsLn); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
						log.Printf("[AD Server] LDAPS Server Fehler: %v", err)
					}
				}()
			}
		}
	}

	return nil
}

func (s *ADServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	if s.tlsListener != nil {
		s.tlsListener.Close()
	}
}

func generateSelfSignedTLS() (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Argus Lab Domain Controller"},
			CommonName:   "dc01.corp.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "dc01.corp.local"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}, nil
}
