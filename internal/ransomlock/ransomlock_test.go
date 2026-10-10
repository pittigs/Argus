package ransomlock

import (
	"testing"
)

func TestRansomwareLockdownEngine(t *testing.T) {
	rle := NewRansomwareLockdownEngine()

	accountDisabled := false
	disableFunc := func(sam string) error {
		accountDisabled = true
		return nil
	}

	event := rle.TriggerEmergencyLockdown(
		"compromised.user",
		"CANARY_FILE_TAMPER",
		120,
		[]string{"DL_FS_Finance_Accounting_Modify", "DL_FS_Project_Docs_ReadWrite"},
		disableFunc,
	)

	if !event.AccountDisabled || !accountDisabled {
		t.Fatalf("expected account to be disabled")
	}

	if len(event.SharesRevoked) != 2 {
		t.Fatalf("expected 2 shares revoked")
	}

	if event.IsolationTimeMs <= 0 {
		t.Fatalf("expected non-zero isolation time")
	}

	if !IsCanaryFile("confidential_canary_trap.docx") {
		t.Fatalf("expected canary file to be detected")
	}
}
