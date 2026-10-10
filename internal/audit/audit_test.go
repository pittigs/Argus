package audit_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/db"
)

func TestAuditLogTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_audit.db")

	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	defer database.Close()

	svc := audit.NewService(database)

	// 1. Initial verification after genesis
	res, err := svc.VerifyChain()
	if err != nil {
		t.Fatalf("Failed to verify chain: %v", err)
	}
	if res.IsCompromised {
		t.Fatalf("Chain should not be compromised initially: %s", res.Message)
	}
	if res.VerifiedCount != 1 {
		t.Fatalf("Expected 1 genesis entry, got %d", res.VerifiedCount)
	}

	// 2. Add some audit entries
	e1, err := svc.Record(audit.LogEntryInput{
		ActorID:       "admin-1",
		ActorUsername: "admin",
		ActorIP:       "127.0.0.1",
		UserAgent:     "Go-Test",
		Action:        "user.create",
		ResourceType:  "user",
		ResourceID:    "alice",
		Status:        "SUCCESS",
		NewValues:     map[string]string{"username": "alice", "role": "engineer"},
		Reason:        "Onboarding new engineer",
	})
	if err != nil {
		t.Fatalf("Failed to record entry 1: %v", err)
	}

	e2, err := svc.Record(audit.LogEntryInput{
		ActorID:       "admin-1",
		ActorUsername: "admin",
		ActorIP:       "127.0.0.1",
		UserAgent:     "Go-Test",
		Action:        "role.update",
		ResourceType:  "role",
		ResourceID:    "engineer",
		Status:        "SUCCESS",
		OldValues:     map[string]string{"permissions": "read"},
		NewValues:     map[string]string{"permissions": "read,write"},
		Reason:        "Granting write permissions",
	})
	if err != nil {
		t.Fatalf("Failed to record entry 2: %v", err)
	}

	// 3. Verify valid chain with 3 entries
	res, err = svc.VerifyChain()
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if res.IsCompromised {
		t.Fatalf("Expected chain to be valid, but got: %s", res.Message)
	}
	if res.VerifiedCount != 3 {
		t.Fatalf("Expected 3 verified entries, got %d", res.VerifiedCount)
	}

	// 4. Test Export CSV and JSON
	csvData, err := svc.ExportCSV(audit.FilterParams{})
	if err != nil {
		t.Fatalf("Failed to export CSV: %v", err)
	}
	if len(csvData) == 0 {
		t.Fatalf("CSV data is empty")
	}

	jsonData, err := svc.ExportJSON(audit.FilterParams{})
	if err != nil {
		t.Fatalf("Failed to export JSON: %v", err)
	}
	if len(jsonData) == 0 {
		t.Fatalf("JSON data is empty")
	}

	// 5. Simulate unauthorized tampering: secretly modify an old audit log row directly in SQLite
	_, err = database.Exec("UPDATE audit_logs SET action = 'malicious.hack' WHERE id = ?", e1.ID)
	if err != nil {
		t.Fatalf("Failed to simulate tampering: %v", err)
	}

	// 6. Verification MUST detect tampering!
	tamperRes, err := svc.VerifyChain()
	if err != nil {
		t.Fatalf("Verification error during tamper check: %v", err)
	}
	if !tamperRes.IsCompromised {
		t.Fatalf("Chain verification failed to detect unauthorized data change!")
	}
	t.Logf("Tamper successfully detected! Message: %s (Broken Index: %d)", tamperRes.Message, tamperRes.BrokenIndex)

	_ = e2
	_ = time.Second
}
