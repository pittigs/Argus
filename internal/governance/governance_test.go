package governance

import (
	"testing"
	"time"
)

func TestGovernancePackage(t *testing.T) {
	// 1. BreakGlass
	bg := NewBreakGlassManager()
	sess, err := bg.RequestEmergencyAccess("bg-admin", "sarah.connor", "INC-12345", "Total DC Outage")
	if err != nil {
		t.Fatalf("failed to request break glass: %v", err)
	}

	// Self-approval must fail
	_, _, err = bg.ApproveEmergencyAccess(sess.ID, "sarah.connor")
	if err == nil {
		t.Fatalf("expected self-approval to fail")
	}

	// Dual-control approval
	activeSess, secret, err := bg.ApproveEmergencyAccess(sess.ID, "admin")
	if err != nil || activeSess.Status != "ACTIVE" || secret == "" {
		t.Fatalf("expected active session with secret")
	}

	// 2. Ephemeral Credentials
	ecs := NewEphemeralCredentialService()
	cred, err := ecs.IssueEphemeralCredential("sarah.connor", "SSH_CERT", 30*time.Minute)
	if err != nil || cred.Secret == "" {
		t.Fatalf("failed to issue ephemeral cred")
	}

	// 3. SoD Conflict Engine
	sod := NewSoDEngine()
	violations := sod.CheckUserConflicts("bad.user", "Bad User", []string{
		"DL_FS_Finance_Accounting_Modify",
		"DL_FS_Finance_Payout_Approval",
	})
	if len(violations) == 0 {
		t.Fatalf("expected SoD violation for toxic pair")
	}

	// 4. Certification Campaigns
	ccs := NewCertificationCampaignService()
	camps := ccs.ListCampaigns()
	if len(camps) == 0 {
		t.Fatalf("expected campaigns")
	}
	err = ccs.DecideItem(camps[0].ID, camps[0].Items[0].ID, "CERTIFIED", "Geprüft und bestätigt")
	if err != nil {
		t.Fatalf("failed to decide item: %v", err)
	}

	// 5. Session Audit Recorder
	sar := NewSessionAuditRecorder()
	recs := sar.ListRecords()
	if len(recs) == 0 {
		t.Fatalf("expected session records")
	}
}
