package kerberos

import (
	"strings"
	"sync"
	"time"
)

// -------------------------------------------------------------
// Kerberos & Ticket Security Engine
// -------------------------------------------------------------

type KerberosAccountRisk struct {
	SAMAccountName  string   `json:"sam_account_name"`
	SPNs            []string `json:"spns"`
	EncryptionTypes []string `json:"encryption_types"`
	PreAuthRequired bool     `json:"preauth_required"`
	RiskScore       int      `json:"risk_score"`       // 0 to 100
	Vulnerabilities []string `json:"vulnerabilities"`  // "KERBEROASTING_RC4", "ASREP_ROASTING_NO_PREAUTH"
	Recommendation  string   `json:"recommendation"`
}

type TicketAnomalyAlert struct {
	AlertID        string    `json:"alert_id"`
	Type           string    `json:"type"` // "GOLDEN_TICKET_SUSPECTED", "SILVER_TICKET_SUSPECTED", "ANOMALOUS_LIFETIME"
	AccountName    string    `json:"account_name"`
	ClientIP       string    `json:"client_ip"`
	DetectedAt     time.Time `json:"detected_at"`
	Severity       string    `json:"severity"` // "CRITICAL", "HIGH"
	Details        string    `json:"details"`
}

type KerberosSecurityEngine struct {
	alerts []TicketAnomalyAlert
	mu     sync.RWMutex
}

func NewKerberosSecurityEngine() *KerberosSecurityEngine {
	return &KerberosSecurityEngine{
		alerts: []TicketAnomalyAlert{},
	}
}

// AnalyzeAccountRisks checks for Kerberoasting and AS-REP Roasting weaknesses
func (kse *KerberosSecurityEngine) AnalyzeAccountRisks(accounts []KerberosAccountRisk) []KerberosAccountRisk {
	var evaluated []KerberosAccountRisk

	for _, acc := range accounts {
		risk := acc
		risk.Vulnerabilities = []string{}
		score := 0

		// 1. Kerberoasting check: SPN exists with weak encryption (RC4 or DES)
		if len(risk.SPNs) > 0 {
			hasWeakEnc := false
			for _, enc := range risk.EncryptionTypes {
				encUpper := strings.ToUpper(enc)
				if strings.Contains(encUpper, "RC4") || strings.Contains(encUpper, "DES") {
					hasWeakEnc = true
					break
				}
			}
			if hasWeakEnc || len(risk.EncryptionTypes) == 0 {
				risk.Vulnerabilities = append(risk.Vulnerabilities, "KERBEROASTING_RC4_EXPOSED")
				score += 50
				risk.Recommendation = "Dienstkonto verwendet schwache Kerberos-Verschlüsselung (RC4). Erzwingen Sie AES-256 (msDS-SupportedEncryptionTypes: 0x18)."
			}
		}

		// 2. AS-REP Roasting check: DONT_REQ_PREAUTH flag set
		if !risk.PreAuthRequired {
			risk.Vulnerabilities = append(risk.Vulnerabilities, "ASREP_ROASTING_NO_PREAUTH")
			score += 45
			if risk.Recommendation != "" {
				risk.Recommendation += " "
			}
			risk.Recommendation += "Kerberos-Vorauthentifizierung ist deaktiviert (DONT_REQ_PREAUTH). Aktivieren Sie Vorauthentifizierung umgehend im AD."
		}

		risk.RiskScore = score
		if len(risk.Vulnerabilities) > 0 {
			evaluated = append(evaluated, risk)
		}
	}

	return evaluated
}

// InspectTicketRequest simulates detection of Golden / Silver Ticket anomalies
func (kse *KerberosSecurityEngine) InspectTicketRequest(account string, ticketLifetimeHours int, pacValid bool, clientIP string) *TicketAnomalyAlert {
	kse.mu.Lock()
	defer kse.mu.Unlock()

	var alert *TicketAnomalyAlert

	// Golden Ticket heuristic: anomalous lifetime (> 10h) or forged PAC checksum
	if !pacValid {
		alert = &TicketAnomalyAlert{
			AlertID:     "kt-pac-forge-001",
			Type:        "GOLDEN_TICKET_SUSPECTED",
			AccountName: account,
			ClientIP:    clientIP,
			DetectedAt:  time.Now().UTC(),
			Severity:    "CRITICAL",
			Details:     "Ungültige oder gefälschte PAC-Signatur (Privilege Attribute Certificate) erkannt. Möglicher Golden Ticket Angriff mit kompromittiertem krbtgt-Schlüssel!",
		}
	} else if ticketLifetimeHours > 12 {
		alert = &TicketAnomalyAlert{
			AlertID:     "kt-life-anom-002",
			Type:        "ANOMALOUS_LIFETIME",
			AccountName: account,
			ClientIP:    clientIP,
			DetectedAt:  time.Now().UTC(),
			Severity:    "HIGH",
			Details:     "Ungewöhnliche Kerberos TGT Ticket-Gültigkeitsdauer (> 12 Stunden). Verdacht auf synthetisch erstelltes Ticket.",
		}
	}

	if alert != nil {
		kse.alerts = append(kse.alerts, *alert)
	}

	return alert
}

func (kse *KerberosSecurityEngine) ListAlerts() []TicketAnomalyAlert {
	kse.mu.RLock()
	defer kse.mu.RUnlock()
	res := make([]TicketAnomalyAlert, len(kse.alerts))
	copy(res, kse.alerts)
	return res
}
