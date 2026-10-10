package policy

import (
	"testing"
	"time"
)

func TestPolicyPackage(t *testing.T) {
	// 1. ABAC & Policy-as-Code
	engine := NewPolicyEngine()
	rules := engine.ListPolicies()
	if len(rules) < 3 {
		t.Fatalf("expected at least 3 policies")
	}

	// Test non-compliant device on production resource
	ctx := ABACContext{
		Username:        "sarah.connor",
		Department:      "Software Engineering",
		DeviceCompliant: false,
		RequestTime:     time.Date(2026, 10, 10, 14, 0, 0, 0, time.UTC),
		Action:          "production:deploy",
		Resource:        "production/api-gateway",
	}
	res := engine.Evaluate(ctx)
	if res.Allowed {
		t.Fatalf("expected non-compliant device to be DENIED on production")
	}

	// 2. Role Mining
	miner := NewRoleMiningEngine()
	userGroups := map[string][]string{
		"u1": {"gA", "gB", "gC"},
		"u2": {"gA", "gB"},
		"u3": {"gA", "gB", "gD"},
	}
	cands := miner.MineRoles(userGroups)
	if len(cands) == 0 {
		t.Fatalf("expected role candidates")
	}

	// 3. Orphan Detector
	detector := NewOrphanDetector()
	past := time.Now().UTC().Add(-100 * 24 * time.Hour)
	orphans := detector.ScanAccounts([]UserAccountStatus{
		{
			Username:    "inactive.user",
			FullName:    "Inactive User",
			Status:      "active",
			LastLoginAt: &past,
			Groups:      []string{"Domain Users"},
		},
	})
	if len(orphans) == 0 || orphans[0].IssueType != "DORMANT_LOGIN" {
		t.Fatalf("expected dormant account detected")
	}

	// 4. Shadow Admin
	analyzer := NewShadowAdminAnalyzer()
	report := analyzer.AnalyzeGraph()
	if report.TotalPathsFound == 0 || len(report.Edges) == 0 {
		t.Fatalf("expected escalation paths")
	}
}
