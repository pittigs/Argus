package lifecycle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pittigs/argus/internal/audit"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/directory"
	"github.com/pittigs/argus/internal/service"
)

func setupTestLifecycle(t *testing.T) (*Service, *db.DB, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "argus_lc_test_*")
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
	mgmtSvc := service.NewManagementService(database, auditSvc)
	dirMgr, err := directory.NewManager(database, auditSvc)
	if err != nil {
		database.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create dir manager: %v", err)
	}

	lcSvc := NewService(database, auditSvc, dirMgr, mgmtSvc)
	cleanup := func() {
		database.Close()
		os.RemoveAll(tmpDir)
	}

	return lcSvc, database, cleanup
}

func TestLifecycleBaselineAndList(t *testing.T) {
	svc, _, cleanup := setupTestLifecycle(t)
	defer cleanup()

	list, err := svc.ListEmployees("", "")
	if err != nil {
		t.Fatalf("failed to list employees: %v", err)
	}
	if len(list) < 4 {
		t.Fatalf("expected at least 4 baseline employees, got %d", len(list))
	}

	stats, err := svc.GetLifecycleStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.TotalEmployees < 4 {
		t.Errorf("expected at least 4 total employees in stats, got %d", stats.TotalEmployees)
	}
}

func TestAutomatedOnboardingAndOffboarding(t *testing.T) {
	svc, _, cleanup := setupTestLifecycle(t)
	defer cleanup()

	actor := ActorInfo{
		ID:        "admin-id",
		Username:  "admin",
		IPAddress: "127.0.0.1",
		UserAgent: "ArgusTest/1.0",
	}

	// 1. Onboard a new software engineer
	onboardInput := OnboardInput{
		GivenName:       "Lukas",
		Surname:         "Bauer",
		Department:      "Software Engineering",
		JobTitle:        "Fullstack Developer",
		StartDate:       "2026-10-15",
		Manager:         "Sarah Connor",
		ProfilePreset:   "it_dev",
		AutoCreateIAM:   true,
		AutoCreateAD:    true,
		AutoAssignAGDLP: true,
		Notes:           "Campus hire 2026",
	}

	emp, err := svc.Onboard(onboardInput, actor)
	if err != nil {
		t.Fatalf("failed to onboard employee: %v", err)
	}

	if emp.SAMAccountName != "lukas.bauer" {
		t.Errorf("expected samAccountName 'lukas.bauer', got %s", emp.SAMAccountName)
	}
	if emp.Stage != "pre_boarding" {
		t.Errorf("expected stage 'pre_boarding' for future date, got %s", emp.Stage)
	}
	if len(emp.AssignedGroups) == 0 {
		t.Errorf("expected assigned groups for it_dev preset")
	}

	// 2. Update Checklist
	emp, err = svc.UpdateChecklist(ChecklistUpdateInput{
		RecordID: emp.ID,
		ItemKey:  "hardware_issued",
		Done:     true,
	}, actor)
	if err != nil {
		t.Fatalf("failed to update checklist: %v", err)
	}
	if !emp.Checklist["hardware_issued"].Completed {
		t.Errorf("expected hardware_issued to be completed")
	}

	// 3. Offboard Lukas Bauer
	offboardInput := OffboardInput{
		SAMAccountName: "lukas.bauer",
		Reason:         "Probezeit beendet auf eigenen Wunsch",
		EffectiveDate:  "2026-10-20",
		RevokeAccess:   true,
		ArchiveData:    true,
		Notes:          "Austrittsprotokoll vollständig",
	}

	offEmp, err := svc.Offboard(offboardInput, actor)
	if err != nil {
		t.Fatalf("failed to offboard employee: %v", err)
	}
	if offEmp.Stage != "offboarded" {
		t.Errorf("expected stage 'offboarded', got %s", offEmp.Stage)
	}
	if offEmp.AccountEnabled {
		t.Errorf("expected account to be disabled")
	}
	if len(offEmp.AssignedGroups) != 0 {
		t.Errorf("expected 0 assigned groups after offboarding")
	}
}
