package selfhealing

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type DriftIncident struct {
	ID           string    `json:"id"`
	GroupName    string    `json:"group_name"`
	RogueMember  string    `json:"rogue_member"`
	DetectedAt   time.Time `json:"detected_at"`
	RemediatedAt time.Time `json:"remediated_at"`
	Status       string    `json:"status"` // "REMEDIATED", "PENDING", "ALERTED"
	Details      string    `json:"details"`
}

type SelfHealingEngine struct {
	baselineMemberships map[string]map[string]bool // lower(group) -> set of allowed members
	incidents           []DriftIncident
	mu                  sync.RWMutex
}

func NewSelfHealingEngine() *SelfHealingEngine {
	sh := &SelfHealingEngine{
		baselineMemberships: make(map[string]map[string]bool),
		incidents:           []DriftIncident{},
	}

	// Establish initial authorized baseline for Domain Admins
	sh.SetBaseline("Domain Admins", []string{"Administrator", "sarah.connor"})
	sh.SetBaseline("Enterprise Admins", []string{"Administrator"})
	return sh
}

func (sh *SelfHealingEngine) SetBaseline(group string, allowedMembers []string) {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	grpKey := strings.ToLower(group)
	if sh.baselineMemberships[grpKey] == nil {
		sh.baselineMemberships[grpKey] = make(map[string]bool)
	}
	for _, m := range allowedMembers {
		sh.baselineMemberships[grpKey][strings.ToLower(m)] = true
	}
}

// CheckAndRemediate inspects current members against the baseline and auto-reverts unauthorized drift
func (sh *SelfHealingEngine) CheckAndRemediate(group string, currentMembers []string, removeMemberFunc func(group, member string) error) []DriftIncident {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	grpKey := strings.ToLower(group)
	allowed, hasBaseline := sh.baselineMemberships[grpKey]
	if !hasBaseline {
		return nil
	}

	var newIncidents []DriftIncident
	now := time.Now().UTC()

	for _, m := range currentMembers {
		mKey := strings.ToLower(m)
		if !allowed[mKey] {
			// Unauthorized drift detected!
			incident := DriftIncident{
				ID:           fmt.Sprintf("drift-%d", now.UnixNano()),
				GroupName:    group,
				RogueMember:  m,
				DetectedAt:   now,
				RemediatedAt: now,
				Status:       "REMEDIATED",
				Details:      fmt.Sprintf("Nicht autorisierte Mitgliedschaft in '%s' erkannt. Automatischer Revert durchgeführt.", group),
			}

			// Execute remediation callback
			if removeMemberFunc != nil {
				if err := removeMemberFunc(group, m); err != nil {
					incident.Status = "FAILED"
					incident.Details = fmt.Sprintf("Auto-Revert fehlgeschlagen: %v", err)
				}
			}

			sh.incidents = append(sh.incidents, incident)
			newIncidents = append(newIncidents, incident)
		}
	}

	return newIncidents
}

func (sh *SelfHealingEngine) ListIncidents() []DriftIncident {
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	res := make([]DriftIncident, len(sh.incidents))
	copy(res, sh.incidents)
	return res
}
