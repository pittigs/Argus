package adserver

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestADServerLifecycle(t *testing.T) {
	ldapPort := 10399
	ldapsPort := 10646

	srv, err := NewADServer("corp.local", "DC=corp,DC=local", "admin123")
	if err != nil {
		t.Fatalf("failed to create AD server: %v", err)
	}

	err = srv.Start(fmt.Sprintf("127.0.0.1:%d", ldapPort), fmt.Sprintf("127.0.0.1:%d", ldapsPort))
	if err != nil {
		t.Fatalf("failed to start AD server: %v", err)
	}
	defer srv.Stop()

	// Wait 50ms for server to bind
	time.Sleep(50 * time.Millisecond)

	// Test 1: Plain LDAP Connection & Bind
	conn, err := ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ldapPort))
	if err != nil {
		t.Fatalf("failed to connect to LDAP server: %v", err)
	}
	defer conn.Close()

	err = conn.Bind("CN=Administrator,CN=Users,DC=corp,DC=local", "admin123")
	if err != nil {
		t.Fatalf("failed to bind as administrator: %v", err)
	}

	// Test 2: Search Users
	searchReq := ldap.NewSearchRequest(
		"OU=Users,DC=corp,DC=local",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "displayName", "mail"},
		nil,
	)
	sr, err := conn.Search(searchReq)
	if err != nil {
		t.Fatalf("failed to search users: %v", err)
	}
	if len(sr.Entries) == 0 {
		t.Fatalf("expected users in AD server, got 0")
	}

	// Test 3: LDAPS TLS Connection
	tlsConn, err := ldap.DialTLS("tcp", fmt.Sprintf("127.0.0.1:%d", ldapsPort), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("failed to connect via LDAPS TLS: %v", err)
	}
	defer tlsConn.Close()

	err = tlsConn.Bind("CN=Administrator,CN=Users,DC=corp,DC=local", "admin123")
	if err != nil {
		t.Fatalf("failed to bind via LDAPS: %v", err)
	}
}
