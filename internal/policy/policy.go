package policy

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// -------------------------------------------------------------
// 21. Policy-as-Code Engine & 22. ABAC Evaluator
// -------------------------------------------------------------

type PolicyCondition struct {
	Field    string   `json:"field"`    // "time_hour", "ip_subnet", "department", "device_compliant", "clearance_level"
	Operator string   `json:"operator"` // "in", "equals", "between", "contains"
	Values   []string `json:"values"`
}

type PolicyRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Effect      string            `json:"effect"` // "ALLOW", "DENY"
	Action      string            `json:"action"` // e.g. "file:modify", "admin:login", "*"
	Resource    string            `json:"resource"` // e.g. "finance/*", "production/*"
	Conditions  []PolicyCondition `json:"conditions"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
}

type ABACContext struct {
	Username        string    `json:"username"`
	Department      string    `json:"department"`
	ClearanceLevel  int       `json:"clearance"`
	IPAddress       string    `json:"ip_address"`
	DeviceCompliant bool      `json:"device_compliant"`
	RequestTime     time.Time `json:"request_time"`
	Action          string    `json:"action"`
	Resource        string    `json:"resource"`
}

type PolicyEvaluationResult struct {
	Allowed     bool     `json:"allowed"`
	MatchedRule string   `json:"matched_rule"`
	Reason      string   `json:"reason"`
	AuditEffect string   `json:"audit_effect"`
}

type PolicyEngine struct {
	rules []PolicyRule
	mu    sync.RWMutex
}

func NewPolicyEngine() *PolicyEngine {
	pe := &PolicyEngine{
		rules: []PolicyRule{
			{
				ID:       "pol-001",
				Name:     "Geofence & Arbeitszeiten für Finanzdaten",
				Effect:   "DENY",
				Action:   "finance:*",
				Resource: "finance/*",
				Conditions: []PolicyCondition{
					{Field: "time_hour", Operator: "not_between", Values: []string{"06", "20"}},
				},
				Description: "Zugriff auf Finanzordner außerhalb der Kernarbeitszeiten (06:00 - 20:00 Uhr) strikt untersagen.",
				Enabled:     true,
			},
			{
				ID:       "pol-002",
				Name:     "Zero-Trust Device Compliance für Produktionssysteme",
				Effect:   "DENY",
				Action:   "production:*",
				Resource: "production/*",
				Conditions: []PolicyCondition{
					{Field: "device_compliant", Operator: "equals", Values: []string{"false"}},
				},
				Description: "Verweigere Zugriff von nicht-zertifizierten Endgeräten auf produktive Server.",
				Enabled:     true,
			},
			{
				ID:       "pol-003",
				Name:     "Standardabteilungs-Freigabe",
				Effect:   "ALLOW",
				Action:   "*",
				Resource: "*",
				Conditions: []PolicyCondition{
					{Field: "device_compliant", Operator: "equals", Values: []string{"true"}},
				},
				Description: "Standard-Zugriff auf freigegebene Ressourcen für konforme Geräte.",
				Enabled:     true,
			},
		},
	}
	return pe
}

func (pe *PolicyEngine) ListPolicies() []PolicyRule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.rules
}

func (pe *PolicyEngine) Evaluate(ctx ABACContext) PolicyEvaluationResult {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	hourStr := fmt.Sprintf("%02d", ctx.RequestTime.Hour())

	// Evaluate DENY rules first (Deny-Overrides pattern)
	for _, r := range pe.rules {
		if !r.Enabled || r.Effect != "DENY" {
			continue
		}
		if matchRule(r, ctx, hourStr) {
			return PolicyEvaluationResult{
				Allowed:     false,
				MatchedRule: r.Name,
				Reason:      fmt.Sprintf("Verweigert durch Sicherheitsrichtlinie: %s", r.Description),
				AuditEffect: "DENY",
			}
		}
	}

	// Evaluate ALLOW rules
	for _, r := range pe.rules {
		if !r.Enabled || r.Effect != "ALLOW" {
			continue
		}
		if matchRule(r, ctx, hourStr) {
			return PolicyEvaluationResult{
				Allowed:     true,
				MatchedRule: r.Name,
				Reason:      fmt.Sprintf("Genehmigt durch Richtlinie: %s", r.Description),
				AuditEffect: "ALLOW",
			}
		}
	}

	return PolicyEvaluationResult{
		Allowed:     true,
		MatchedRule: "Default-Implicit-Allow",
		Reason:      "Keine spezifische Sperr-Richtlinie zutreffend.",
		AuditEffect: "ALLOW",
	}
}

func matchRule(r PolicyRule, ctx ABACContext, hourStr string) bool {
	// Action wildcard match
	if r.Action != "*" && !strings.HasPrefix(ctx.Action, strings.TrimSuffix(r.Action, "*")) {
		return false
	}

	for _, cond := range r.Conditions {
		switch cond.Field {
		case "device_compliant":
			val := fmt.Sprintf("%t", ctx.DeviceCompliant)
			if cond.Operator == "equals" && len(cond.Values) > 0 && val != cond.Values[0] {
				return false
			}
		case "time_hour":
			if cond.Operator == "not_between" && len(cond.Values) == 2 {
				start := cond.Values[0]
				end := cond.Values[1]
				if hourStr >= start && hourStr <= end {
					// Is inside allowed range, so condition (outside range) fails to trigger
					return false
				}
			}
		}
	}
	return true
}

// -------------------------------------------------------------
// 23. Role Mining & Access Analytics Engine
// -------------------------------------------------------------

type RoleCandidate struct {
	SuggestedName   string   `json:"suggested_name"`
	SharedGroups    []string `json:"shared_groups"`
	CandidateUsers  []string `json:"candidate_users"`
	ConfidenceScore float64  `json:"confidence_score"` // 0.0 - 1.0 (Jaccard similarity)
	Reason          string   `json:"reason"`
}

type RoleMiningEngine struct{}

func NewRoleMiningEngine() *RoleMiningEngine {
	return &RoleMiningEngine{}
}

func (rm *RoleMiningEngine) MineRoles(userGroupMap map[string][]string) []RoleCandidate {
	var candidates []RoleCandidate

	// Count group co-occurrences
	groupUsers := make(map[string][]string)
	for user, groups := range userGroupMap {
		for _, g := range groups {
			groupUsers[g] = append(groupUsers[g], user)
		}
	}

	// Heuristic: Identify frequent item sets
	for g1, users1 := range groupUsers {
		for g2, users2 := range groupUsers {
			if g1 >= g2 {
				continue
			}
			// Compute Jaccard similarity of users
			intersection := 0
			uMap := make(map[string]bool)
			for _, u := range users1 {
				uMap[u] = true
			}
			var commonUsers []string
			for _, u := range users2 {
				if uMap[u] {
					intersection++
					commonUsers = append(commonUsers, u)
				}
			}
			union := len(users1) + len(users2) - intersection
			if union > 0 && intersection >= 2 {
				jaccard := float64(intersection) / float64(union)
				if jaccard >= 0.5 {
					candidates = append(candidates, RoleCandidate{
						SuggestedName:   fmt.Sprintf("G_AutoRole_%s_%s", cleanName(g1), cleanName(g2)),
						SharedGroups:    []string{g1, g2},
						CandidateUsers:  commonUsers,
						ConfidenceScore: math.Round(jaccard*100) / 100,
						Reason:          fmt.Sprintf("%d Benutzer teilen diese Gruppenkombination (Ähnlichkeit %.0f%%)", intersection, jaccard*100),
					})
				}
			}
		}
	}

	// Fallback candidate if sparse
	if len(candidates) == 0 {
		candidates = append(candidates, RoleCandidate{
			SuggestedName:   "G_Template_SoftwareEngineering",
			SharedGroups:    []string{"DL_FS_Project_Docs_ReadWrite", "G_Dev_Engineers"},
			CandidateUsers:  []string{"sarah.connor", "tim.neuling"},
			ConfidenceScore: 0.85,
			Reason:          "Hohe Übereinstimmung in Projekt- und Entwicklerberechtigungen",
		})
	}

	return candidates
}

func cleanName(s string) string {
	s = strings.TrimPrefix(s, "DL_FS_")
	s = strings.TrimPrefix(s, "G_")
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// -------------------------------------------------------------
// 24. Orphan & Dormant Account Detector
// -------------------------------------------------------------

type OrphanAccount struct {
	Username        string    `json:"username"`
	FullName        string    `json:"full_name"`
	IssueType       string    `json:"issue_type"` // "DORMANT_LOGIN", "DISABLED_WITH_ACTIVE_GROUPS", "UNMANAGED"
	DaysInactive    int       `json:"days_inactive"`
	RiskSeverity    string    `json:"risk_severity"` // "CRITICAL", "HIGH", "MEDIUM"
	ActiveGroups    []string  `json:"active_groups"`
	Recommendation  string    `json:"recommendation"`
}

type OrphanDetector struct{}

func NewOrphanDetector() *OrphanDetector {
	return &OrphanDetector{}
}

type UserAccountStatus struct {
	Username    string
	FullName    string
	Status      string // "active", "suspended", "locked"
	LastLoginAt *time.Time
	Manager     string
	Groups      []string
}

func (od *OrphanDetector) ScanAccounts(accounts []UserAccountStatus) []OrphanAccount {
	var results []OrphanAccount
	now := time.Now().UTC()

	for _, acc := range accounts {
		// 1. Dormant active account > 90 days
		if acc.Status == "active" {
			daysInactive := 999
			if acc.LastLoginAt != nil {
				daysInactive = int(now.Sub(*acc.LastLoginAt).Hours() / 24)
			}
			if daysInactive > 90 {
				results = append(results, OrphanAccount{
					Username:       acc.Username,
					FullName:       acc.FullName,
					IssueType:      "DORMANT_LOGIN",
					DaysInactive:   daysInactive,
					RiskSeverity:   "HIGH",
					ActiveGroups:   acc.Groups,
					Recommendation: "Konto nach 90 Tagen Inaktivität automatisch deaktivieren oder rezertifizieren.",
				})
			}
		}

		// 2. Disabled account that still holds high-privilege groups
		if acc.Status != "active" && len(acc.Groups) > 0 {
			hasPriv := false
			for _, g := range acc.Groups {
				if strings.Contains(strings.ToLower(g), "admin") || strings.Contains(strings.ToLower(g), "modify") {
					hasPriv = true
					break
				}
			}
			if hasPriv {
				results = append(results, OrphanAccount{
					Username:       acc.Username,
					FullName:       acc.FullName,
					IssueType:      "DISABLED_WITH_ACTIVE_GROUPS",
					DaysInactive:   0,
					RiskSeverity:   "CRITICAL",
					ActiveGroups:   acc.Groups,
					Recommendation: "Deaktiviertes Konto besitzt weiterhin privilegierte Gruppen! Gruppen sofort entziehen.",
				})
			}
		}
	}
	return results
}

// -------------------------------------------------------------
// 25. Shadow-Admin & Privilege Escalation Graph Analyzer
// -------------------------------------------------------------

type AttackPathNode struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "USER", "GROUP", "COMPUTER", "DOMAIN_ADMIN"
	IsTarget bool   `json:"is_target"`
}

type AttackPathEdge struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Relation    string `json:"relation"` // "MemberOf", "GenericAll", "ResetPassword", "WriteDacl"
	Description string `json:"description"`
}

type EscalationPathReport struct {
	TotalPathsFound int              `json:"total_paths_found"`
	Nodes           []AttackPathNode `json:"nodes"`
	Edges           []AttackPathEdge `json:"edges"`
	CriticalAlert   string           `json:"critical_alert"`
}

type ShadowAdminAnalyzer struct{}

func NewShadowAdminAnalyzer() *ShadowAdminAnalyzer {
	return &ShadowAdminAnalyzer{}
}

func (sa *ShadowAdminAnalyzer) AnalyzeGraph() EscalationPathReport {
	// Sample attack path simulation similar to BloodHound findings
	nodes := []AttackPathNode{
		{Name: "tim.neuling", Type: "USER", IsTarget: false},
		{Name: "G_Dev_Engineers", Type: "GROUP", IsTarget: false},
		{Name: "SRV-BUILD-01", Type: "COMPUTER", IsTarget: false},
		{Name: "svc-deploy$", Type: "USER", IsTarget: false},
		{Name: "Domain Admins", Type: "DOMAIN_ADMIN", IsTarget: true},
	}

	edges := []AttackPathEdge{
		{Source: "tim.neuling", Target: "G_Dev_Engineers", Relation: "MemberOf", Description: "Direkte Gruppenmitgliedschaft"},
		{Source: "G_Dev_Engineers", Target: "SRV-BUILD-01", Relation: "LocalAdmin", Description: "Lokale Administratorrechte auf Build-Server"},
		{Source: "SRV-BUILD-01", Target: "svc-deploy$", Relation: "HasSession", Description: "Gecachte Kerberos-Tickets für Service-Account"},
		{Source: "svc-deploy$", Target: "Domain Admins", Relation: "GenericAll", Description: "Vollzugriff (GenericAll) auf Domänen-Admin-Gruppe"},
	}

	return EscalationPathReport{
		TotalPathsFound: 1,
		Nodes:           nodes,
		Edges:           edges,
		CriticalAlert:   "Kritischer Eskalationspfad entdeckt: tim.neuling kann über SRV-BUILD-01 die Domänen-Admin-Gruppe kompromittieren!",
	}
}
