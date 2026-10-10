package directory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/db"
)

func setupTestManager(t *testing.T) (*Manager, *db.DB, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "argus_ent_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open test db: %v", err)
	}
	auditSvc := audit.NewService(database)
	mgr, err := NewManager(database, auditSvc)
	if err != nil {
		database.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to init manager: %v", err)
	}
	cleanup := func() {
		database.Close()
		os.RemoveAll(tmpDir)
	}
	return mgr, database, cleanup
}

func TestCSVBulkImport(t *testing.T) {
	mgr, _, cleanup := setupTestManager(t)
	defer cleanup()
	actor := ActorInfo{ID: "admin1", Username: "admin", IPAddress: "127.0.0.1", UserAgent: "Test"}

	csvData := `sAMAccountName,GivenName,Surname,Email,Department,JobTitle,Password,GlobalGroups
t.mueller,Thomas,Mueller,t.mueller@corp.local,Finanzen,Analyst,SecretPass123!,G_Finanzen_Mitarbeiter
a.schmidt,Anna,Schmidt,a.schmidt@corp.local,IT,Admin,AdminPass123!,G_IT_Admin
`

	result, err := mgr.BulkImportUsers(csvData, actor)
	if err != nil {
		t.Fatalf("BulkImportUsers failed: %v", err)
	}

	if result.TotalProcessed != 2 {
		t.Errorf("expected 2 processed, got %d", result.TotalProcessed)
	}
	if result.SuccessCount != 2 {
		t.Errorf("expected 2 successes, got %d", result.SuccessCount)
	}
	if result.FailureCount != 0 {
		t.Errorf("expected 0 failures, got %d", result.FailureCount)
	}

	// Verify user exists in provider
	u, err := mgr.activeProvider().GetUser("t.mueller")
	if err != nil || u == nil {
		t.Fatalf("user t.mueller was not created")
	}
	if u.DisplayName != "Thomas Mueller" {
		t.Errorf("expected display name 'Thomas Mueller', got '%s'", u.DisplayName)
	}

	// Check sample CSV generator
	sample := GetSampleCSV()
	if !strings.Contains(sample, "sAMAccountName") {
		t.Errorf("sample CSV missing sAMAccountName header")
	}
}

func TestJITTemporaryMemberships(t *testing.T) {
	mgr, _, cleanup := setupTestManager(t)
	defer cleanup()
	actor := ActorInfo{ID: "admin1", Username: "admin", IPAddress: "127.0.0.1", UserAgent: "Test"}

	// Create a test user & group first
	_, _ = mgr.CreateUser(CreateADUserInput{
		SAMAccountName: "jit.test",
		GivenName:      "JIT",
		Surname:        "Tester",
		DisplayName:    "JIT Tester",
		Enabled:        true,
	}, actor)

	_, _ = mgr.CreateGroup("DL_FS_Test_Temp_RW", "Temporary group", "DomainLocal", actor)

	// Grant temporary membership for 2 hours
	req := CreateJITRequest{
		UserSAM:       "jit.test",
		GroupName:     "DL_FS_Test_Temp_RW",
		DurationHours: 2,
		Reason:        "Production Maintenance Window #104",
	}

	jitItem, err := mgr.CreateTemporaryMembership(req, actor)
	if err != nil {
		t.Fatalf("CreateTemporaryMembership failed: %v", err)
	}

	if jitItem.Status != "active" {
		t.Errorf("expected status 'active', got '%s'", jitItem.Status)
	}

	// Verify user is in group
	grp, _ := mgr.activeProvider().GetGroup("DL_FS_Test_Temp_RW")
	found := false
	for _, m := range grp.Members {
		if m == "jit.test" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("user jit.test should be member of DL_FS_Test_Temp_RW")
	}

	// List active
	list, err := mgr.ListActiveTemporaryMemberships()
	if err != nil {
		t.Fatalf("ListActiveTemporaryMemberships failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 active JIT assignment, got %d", len(list))
	}

	// Manual early revoke
	err = mgr.RevokeTemporaryMembership(jitItem.ID, actor)
	if err != nil {
		t.Fatalf("RevokeTemporaryMembership failed: %v", err)
	}

	// Verify user removed from group
	grpAfter, _ := mgr.activeProvider().GetGroup("DL_FS_Test_Temp_RW")
	for _, m := range grpAfter.Members {
		if m == "jit.test" {
			t.Errorf("user jit.test should have been removed after revocation")
		}
	}
}

func TestDualControlApprovals(t *testing.T) {
	mgr, _, cleanup := setupTestManager(t)
	defer cleanup()
	requester := ActorInfo{ID: "usr1", Username: "requester_bob", IPAddress: "127.0.0.1", UserAgent: "Test"}
	approver := ActorInfo{ID: "adm1", Username: "master_admin", IPAddress: "127.0.0.1", UserAgent: "Test"}

	// Create user and group
	_, _ = mgr.CreateUser(CreateADUserInput{
		SAMAccountName: "bob.priv",
		GivenName:      "Bob",
		Surname:        "Privileged",
		DisplayName:    "Bob Privileged",
		Enabled:        true,
	}, approver)

	_, _ = mgr.CreateGroup("DL_FS_Vorstand_Vertraulich_FC", "Executive confidential", "DomainLocal", approver)

	// Bob requests membership in sensitive group
	approval, err := mgr.CreateApprovalRequest(CreateApprovalInput{
		ActionType:     "ad:membership:grant",
		TargetResource: "DL_FS_Vorstand_Vertraulich_FC",
		PayloadJSON:    `{"group_name":"DL_FS_Vorstand_Vertraulich_FC","member":"bob.priv"}`,
		Reason:         "Need executive budget files for quarterly audit",
	}, requester)
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}

	if approval.Status != "pending" {
		t.Errorf("expected status 'pending', got '%s'", approval.Status)
	}

	// Vier-Augen-Prinzip: Bob cannot approve his own request!
	_, err = mgr.ResolveApprovalRequest(approval.ID, ResolveApprovalInput{
		Decision: "approved",
		Notes:    "Self approval should fail",
	}, requester)
	if err == nil {
		t.Fatalf("expected self-approval to fail under Vier-Augen-Prinzip")
	}

	// 2nd Administrator approves
	resolved, err := mgr.ResolveApprovalRequest(approval.ID, ResolveApprovalInput{
		Decision: "approved",
		Notes:    "Freigabe erteilt nach Ruecksprache mit CFO",
	}, approver)
	if err != nil {
		t.Fatalf("ResolveApprovalRequest by 2nd admin failed: %v", err)
	}

	if resolved.Status != "approved" {
		t.Errorf("expected status 'approved', got '%s'", resolved.Status)
	}

	// Check member was automatically added
	grp, _ := mgr.activeProvider().GetGroup("DL_FS_Vorstand_Vertraulich_FC")
	found := false
	for _, m := range grp.Members {
		if m == "bob.priv" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("member bob.priv was not added to group upon approval")
	}
}

func TestShareTemplatesAndComplianceReport(t *testing.T) {
	mgr, _, cleanup := setupTestManager(t)
	defer cleanup()
	actor := ActorInfo{ID: "adm1", Username: "admin", IPAddress: "127.0.0.1", UserAgent: "Test"}

	// 1. Templates
	templates := mgr.GetShareTemplates()
	if len(templates) < 3 {
		t.Errorf("expected at least 3 templates, got %d", len(templates))
	}

	applyRes, err := mgr.ApplyShareTemplate(ApplyShareTemplateInput{
		TemplateID: "dept_standard",
		ShareName:  "Marketing",
		Department: "Marketing",
	}, actor)
	if err != nil {
		t.Fatalf("ApplyShareTemplate failed: %v", err)
	}

	if applyRes.FoldersCreated != 3 {
		t.Errorf("expected 3 folders created, got %d", applyRes.FoldersCreated)
	}
	if len(applyRes.CreatedGroups) == 0 {
		t.Errorf("expected groups to be created")
	}

	// 2. Compliance Report
	rep, err := mgr.GenerateComplianceReport()
	if err != nil {
		t.Fatalf("GenerateComplianceReport failed: %v", err)
	}

	if rep.TotalShares == 0 {
		t.Errorf("expected shares in compliance report, got 0")
	}
	if rep.AuditChainHead == "" {
		t.Errorf("audit chain head must not be empty")
	}

	csvBytes := ExportComplianceCSV(rep)
	if len(csvBytes) == 0 || !strings.Contains(string(csvBytes), "Marketing") {
		t.Errorf("CSV export should contain Marketing share")
	}

	htmlCert := GenerateComplianceHTML(rep)
	if !strings.Contains(htmlCert, "Audit Zertifikat") || !strings.Contains(htmlCert, "Marketing") {
		t.Errorf("HTML certificate should contain proper styling and Marketing share")
	}
}
