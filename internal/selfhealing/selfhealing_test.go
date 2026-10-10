package selfhealing

import (
	"testing"
)

func TestSelfHealingEngine(t *testing.T) {
	sh := NewSelfHealingEngine()

	removedMembers := make(map[string]string)
	removeCallback := func(group, member string) error {
		removedMembers[group] = member
		return nil
	}

	// Current members in Domain Admins contains unauthorized rogue member "tim.neuling"
	current := []string{"Administrator", "sarah.connor", "tim.neuling"}

	incidents := sh.CheckAndRemediate("Domain Admins", current, removeCallback)
	if len(incidents) != 1 {
		t.Fatalf("expected 1 drift incident, got %d", len(incidents))
	}

	if incidents[0].RogueMember != "tim.neuling" {
		t.Fatalf("expected rogue member tim.neuling, got %s", incidents[0].RogueMember)
	}

	if incidents[0].Status != "REMEDIATED" {
		t.Fatalf("expected status REMEDIATED, got %s", incidents[0].Status)
	}

	if removedMembers["Domain Admins"] != "tim.neuling" {
		t.Fatalf("expected tim.neuling to be removed via callback")
	}

	if len(sh.ListIncidents()) != 1 {
		t.Fatalf("expected 1 recorded incident")
	}
}
