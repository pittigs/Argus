package kerberos

import (
	"testing"
)

func TestKerberosSecurityEngine(t *testing.T) {
	kse := NewKerberosSecurityEngine()

	accounts := []KerberosAccountRisk{
		{
			SAMAccountName:  "svc-sql$",
			SPNs:            []string{"MSSQLSvc/sql.corp.local:1433"},
			EncryptionTypes: []string{"RC4-HMAC"},
			PreAuthRequired: true,
		},
		{
			SAMAccountName:  "legacy-app",
			SPNs:            []string{},
			EncryptionTypes: []string{"AES256"},
			PreAuthRequired: false, // DONT_REQ_PREAUTH
		},
		{
			SAMAccountName:  "secure-admin",
			SPNs:            []string{},
			EncryptionTypes: []string{"AES256"},
			PreAuthRequired: true,
		},
	}

	evaluated := kse.AnalyzeAccountRisks(accounts)
	if len(evaluated) != 2 {
		t.Fatalf("expected 2 vulnerable accounts, got %d", len(evaluated))
	}

	// Test Golden Ticket alert on invalid PAC
	alert := kse.InspectTicketRequest("Administrator", 10, false, "10.20.1.50")
	if alert == nil || alert.Severity != "CRITICAL" || alert.Type != "GOLDEN_TICKET_SUSPECTED" {
		t.Fatalf("expected critical golden ticket alert on invalid PAC")
	}

	// Test anomalous ticket lifetime
	alert2 := kse.InspectTicketRequest("sarah.connor", 24, true, "10.20.1.51")
	if alert2 == nil || alert2.Severity != "HIGH" {
		t.Fatalf("expected high severity alert on anomalous lifetime")
	}

	if len(kse.ListAlerts()) != 2 {
		t.Fatalf("expected 2 total alerts recorded")
	}
}
