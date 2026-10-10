package governance

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// -------------------------------------------------------------
// 16. Break-Glass / Emergency Access Accounts ("Notfall-Koffer")
// -------------------------------------------------------------

type BreakGlassSession struct {
	ID                string    `json:"id"`
	AccountName       string    `json:"account_name"`     // e.g. "bg-admin-root"
	TriggeredBy       string    `json:"triggered_by"`     // Primary initiator
	Approver1         string    `json:"approver_1"`       // Dual-control approval
	Reason            string    `json:"reason"`
	IncidentTicketID  string    `json:"incident_ticket"`  // e.g. "INC-89421"
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Status            string    `json:"status"`           // "PENDING_APPROVAL", "ACTIVE", "EXPIRED", "REVOKED"
	PostMortemWritten bool      `json:"post_mortem_done"`
	TemporarySecret   string    `json:"temporary_secret,omitempty"` // Returned only once on activation
}

type BreakGlassManager struct {
	sessions map[string]BreakGlassSession
	mu       sync.RWMutex
}

func NewBreakGlassManager() *BreakGlassManager {
	return &BreakGlassManager{
		sessions: make(map[string]BreakGlassSession),
	}
}

func (bg *BreakGlassManager) RequestEmergencyAccess(accountName, triggeredBy, ticketID, reason string) (*BreakGlassSession, error) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	id := fmt.Sprintf("bg-%d", time.Now().UnixNano())
	sess := BreakGlassSession{
		ID:                id,
		AccountName:       accountName,
		TriggeredBy:       triggeredBy,
		Reason:            reason,
		IncidentTicketID:  ticketID,
		IssuedAt:          time.Now().UTC(),
		ExpiresAt:         time.Now().UTC().Add(4 * time.Hour),
		Status:            "PENDING_APPROVAL",
		PostMortemWritten: false,
	}
	bg.sessions[id] = sess
	return &sess, nil
}

func (bg *BreakGlassManager) ApproveEmergencyAccess(id, approver string) (*BreakGlassSession, string, error) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	sess, ok := bg.sessions[id]
	if !ok {
		return nil, "", errors.New("Break-Glass Sitzung nicht gefunden")
	}
	if sess.TriggeredBy == approver {
		return nil, "", errors.New("Vier-Augen-Prinzip: Der Anfragende kann den Notfallzugriff nicht selbst freigeben")
	}
	if sess.Status != "PENDING_APPROVAL" {
		return nil, "", fmt.Errorf("Sitzung ist nicht im Status PENDING_APPROVAL (aktuell: %s)", sess.Status)
	}

	secretBytes := make([]byte, 16)
	rand.Read(secretBytes)
	tempSecret := "BG-" + hex.EncodeToString(secretBytes) + "-SEC!"

	sess.Approver1 = approver
	sess.Status = "ACTIVE"
	sess.TemporarySecret = tempSecret
	bg.sessions[id] = sess

	return &sess, tempSecret, nil
}

func (bg *BreakGlassManager) ListSessions() []BreakGlassSession {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	res := make([]BreakGlassSession, 0, len(bg.sessions))
	for _, s := range bg.sessions {
		// Clean secret from listing
		clean := s
		clean.TemporarySecret = ""
		res = append(res, clean)
	}
	return res
}

// -------------------------------------------------------------
// 17. Ephemeral Dynamic Credentials Generator
// -------------------------------------------------------------

type EphemeralCredential struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Secret    string    `json:"secret"` // High-entropy dynamic secret
	TokenType string    `json:"token_type"` // "DATABASE_TEMP", "SSH_CERT", "LDAP_TEMP"
	TTL       time.Duration `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type EphemeralCredentialService struct {
	creds map[string]EphemeralCredential
	mu    sync.RWMutex
}

func NewEphemeralCredentialService() *EphemeralCredentialService {
	return &EphemeralCredentialService{
		creds: make(map[string]EphemeralCredential),
	}
}

func (ec *EphemeralCredentialService) IssueEphemeralCredential(username, tokenType string, ttl time.Duration) (*EphemeralCredential, error) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	secret := fmt.Sprintf("EPH_%s_%s", strings.ToUpper(tokenType), hex.EncodeToString(b))

	now := time.Now().UTC()
	cred := EphemeralCredential{
		ID:        fmt.Sprintf("eph-%d", now.UnixNano()),
		Username:  username,
		Secret:    secret,
		TokenType: tokenType,
		TTL:       ttl,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Revoked:   false,
	}
	ec.creds[cred.ID] = cred
	return &cred, nil
}

// -------------------------------------------------------------
// 18. Segregation of Duties (SoD) Conflict Detection Engine
// -------------------------------------------------------------

type SoDConflictRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`        // e.g. "DevOps vs Production Deployment"
	Severity    string   `json:"severity"`    // "CRITICAL", "HIGH", "MEDIUM"
	GroupA      string   `json:"group_a"`     // e.g. "DL_FS_Finance_Accounting_Modify"
	GroupB      string   `json:"group_b"`     // e.g. "DL_FS_Finance_Payout_Approval"
	Description string   `json:"description"`
}

type SoDViolation struct {
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Username    string    `json:"username"`
	FullName    string    `json:"full_name"`
	GroupA      string    `json:"group_a"`
	GroupB      string    `json:"group_b"`
	DetectedAt  time.Time `json:"detected_at"`
}

type SoDEngine struct {
	rules []SoDConflictRule
}

func NewSoDEngine() *SoDEngine {
	return &SoDEngine{
		rules: []SoDConflictRule{
			{
				ID:          "sod-001",
				Name:        "Finanzbuchhaltung vs. Auszahlungsfreigabe (Vier-Augen-Verletzung)",
				Severity:    "CRITICAL",
				GroupA:      "DL_FS_Finance_Accounting_Modify",
				GroupB:      "DL_FS_Finance_Payout_Approval",
				Description: "Ein Mitarbeiter darf nicht gleichzeitig Überweisungsdateien bearbeiten und freigeben.",
			},
			{
				ID:          "sod-002",
				Name:        "Software-Entwicklung vs. Domänen-Administration",
				Severity:    "HIGH",
				GroupA:      "G_Dev_Engineers",
				GroupB:      "Domain Admins",
				Description: "Entwicklerkonten dürfen nicht dauerhaft Mitglied der Domain Admins sein.",
			},
			{
				ID:          "sod-003",
				Name:        "Personalakte Vertraulich vs. Externe Dienstleister",
				Severity:    "CRITICAL",
				GroupA:      "DL_FS_HR_Personnel_Confidential_Modify",
				GroupB:      "G_External_Contractors",
				Description: "Externe Dienstleister dürfen keinen Zugriff auf vertrauliche HR-Daten haben.",
			},
		},
	}
}

func (sod *SoDEngine) CheckUserConflicts(username, fullName string, userGroups []string) []SoDViolation {
	groupSet := make(map[string]bool)
	for _, g := range userGroups {
		groupSet[g] = true
	}

	var violations []SoDViolation
	for _, r := range sod.rules {
		if groupSet[r.GroupA] && groupSet[r.GroupB] {
			violations = append(violations, SoDViolation{
				RuleID:     r.ID,
				RuleName:   r.Name,
				Severity:   r.Severity,
				Username:   username,
				FullName:   fullName,
				GroupA:     r.GroupA,
				GroupB:     r.GroupB,
				DetectedAt: time.Now().UTC(),
			})
		}
	}
	return violations
}

func (sod *SoDEngine) ListRules() []SoDConflictRule {
	return sod.rules
}

// -------------------------------------------------------------
// 19. Access Certification & Periodic Recertification Campaigns
// -------------------------------------------------------------

type CertificationItem struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	GroupName   string    `json:"group_name"`
	Manager     string    `json:"manager"`
	Decision    string    `json:"decision"` // "PENDING", "CERTIFIED", "REVOKED"
	DecisionAt  *time.Time `json:"decision_at,omitempty"`
	Comment     string    `json:"comment,omitempty"`
}

type CertificationCampaign struct {
	ID          string              `json:"id"`
	Title       string              `json:"title"` // e.g. "Q4 2026 Privilege Recertification"
	StartedAt   time.Time           `json:"started_at"`
	Deadline    time.Time           `json:"deadline"`
	Status      string              `json:"status"` // "ACTIVE", "COMPLETED", "EXPIRED"
	Items       []CertificationItem `json:"items"`
}

type CertificationCampaignService struct {
	campaigns map[string]CertificationCampaign
	mu        sync.RWMutex
}

func NewCertificationCampaignService() *CertificationCampaignService {
	cs := &CertificationCampaignService{
		campaigns: make(map[string]CertificationCampaign),
	}
	// Initial baseline campaign
	now := time.Now().UTC()
	c := CertificationCampaign{
		ID:        "camp-2026-q4",
		Title:     "Q4 2026 Audit-Rezertifizierung (ISO 27001 Access Control)",
		StartedAt: now.Add(-5 * 24 * time.Hour),
		Deadline:  now.Add(25 * 24 * time.Hour),
		Status:    "ACTIVE",
		Items: []CertificationItem{
			{ID: "ci-01", Username: "sarah.connor", GroupName: "Domain Admins", Manager: "Max Mustermann", Decision: "CERTIFIED"},
			{ID: "ci-02", Username: "tim.neuling", GroupName: "DL_FS_Project_Docs_ReadWrite", Manager: "Sarah Connor", Decision: "PENDING"},
			{ID: "ci-03", Username: "elena.rostova", GroupName: "DL_FS_Finance_Accounting_Modify", Manager: "Vorstand", Decision: "CERTIFIED"},
		},
	}
	cs.campaigns[c.ID] = c
	return cs
}

func (cs *CertificationCampaignService) ListCampaigns() []CertificationCampaign {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	res := make([]CertificationCampaign, 0, len(cs.campaigns))
	for _, c := range cs.campaigns {
		res = append(res, c)
	}
	return res
}

func (cs *CertificationCampaignService) DecideItem(campaignID, itemID, decision, comment string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	camp, ok := cs.campaigns[campaignID]
	if !ok {
		return errors.New("Rezertifizierungskampagne nicht gefunden")
	}

	found := false
	now := time.Now().UTC()
	for i := range camp.Items {
		if camp.Items[i].ID == itemID {
			camp.Items[i].Decision = decision
			camp.Items[i].DecisionAt = &now
			camp.Items[i].Comment = comment
			found = true
			break
		}
	}
	if !found {
		return errors.New("Prüfelement nicht in Kampagne gefunden")
	}
	cs.campaigns[campaignID] = camp
	return nil
}

// -------------------------------------------------------------
// 20. JIT Session Recording & Keystroke Telemetry
// -------------------------------------------------------------

type SessionCommandLog struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	ExitCode  int       `json:"exit_code"`
	RiskTag   string    `json:"risk_tag,omitempty"`
}

type JITSessionRecord struct {
	SessionID  string              `json:"session_id"`
	JITGrantID string              `json:"jit_grant_id"`
	Actor      string              `json:"actor"`
	TargetHost string              `json:"target_host"`
	StartedAt  time.Time           `json:"started_at"`
	EndedAt    *time.Time          `json:"ended_at,omitempty"`
	Commands   []SessionCommandLog `json:"commands"`
}

type SessionAuditRecorder struct {
	sessions map[string]JITSessionRecord
	mu       sync.RWMutex
}

func NewSessionAuditRecorder() *SessionAuditRecorder {
	sar := &SessionAuditRecorder{
		sessions: make(map[string]JITSessionRecord),
	}
	// Initial demo session
	now := time.Now().UTC()
	sar.sessions["sess-001"] = JITSessionRecord{
		SessionID:  "sess-001",
		JITGrantID: "jit-adm-1",
		Actor:      "sarah.connor",
		TargetHost: "srv-dc01.corp.local",
		StartedAt:  now.Add(-40 * time.Minute),
		Commands: []SessionCommandLog{
			{Timestamp: now.Add(-38 * time.Minute), Command: "whoami /groups", ExitCode: 0, RiskTag: "RECON"},
			{Timestamp: now.Add(-35 * time.Minute), Command: "net user test-acc /active:yes", ExitCode: 0, RiskTag: "MODIFICATION"},
			{Timestamp: now.Add(-20 * time.Minute), Command: "exit", ExitCode: 0, RiskTag: "LOGOUT"},
		},
	}
	return sar
}

func (sar *SessionAuditRecorder) ListRecords() []JITSessionRecord {
	sar.mu.RLock()
	defer sar.mu.RUnlock()
	res := make([]JITSessionRecord, 0, len(sar.sessions))
	for _, s := range sar.sessions {
		res = append(res, s)
	}
	return res
}
