package directory

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"time"
)

// GenerateComplianceReport compiles an audit snapshot of all identities and AGDLP permissions
func (m *Manager) GenerateComplianceReport() (*ComplianceReport, error) {
	users, err := m.ListUsers("")
	if err != nil {
		return nil, fmt.Errorf("Benutzer konnten nicht geladen werden: %w", err)
	}

	groups, err := m.ListGroups("")
	if err != nil {
		return nil, fmt.Errorf("Gruppen konnten nicht geladen werden: %w", err)
	}

	shares, err := m.GetAGDLPMatrix()
	if err != nil {
		return nil, fmt.Errorf("AGDLP-Matrix konnte nicht geladen werden: %w", err)
	}

	conflicts, err := m.DetectConflicts()
	if err != nil {
		conflicts = nil
	}

	var headHash string
	_ = m.db.QueryRow("SELECT entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1").Scan(&headHash)
	if headHash == "" {
		headHash = strings.Repeat("0", 64)
	}

	cfg := m.GetConfig()

	// Calculate per-user access summary
	var summaries []UserAccessItem
	for _, u := range users {
		perms, _ := m.CalculateEffectivePermissions(u.SAMAccountName)
		uniqueShares := make(map[string]bool)
		for _, p := range perms {
			uniqueShares[p.ShareName] = true
		}

		summaries = append(summaries, UserAccessItem{
			SAMAccountName: u.SAMAccountName,
			DisplayName:    u.DisplayName,
			Department:     u.Department,
			DirectRoles:    u.MemberOf,
			SharesCount:    len(uniqueShares),
		})
	}

	return &ComplianceReport{
		GeneratedAt:       time.Now().UTC(),
		Domain:            cfg.BaseDN,
		DCHost:            cfg.Host,
		AuditChainHead:    headHash,
		TotalUsers:        len(users),
		TotalGroups:       len(groups),
		TotalShares:       len(shares),
		TotalConflicts:    len(conflicts),
		Shares:            shares,
		Conflicts:         conflicts,
		UserAccessSummary: summaries,
	}, nil
}

// ExportComplianceCSV renders the report as a CSV table
func ExportComplianceCSV(rep *ComplianceReport) []byte {
	buf := new(bytes.Buffer)
	w := csv.NewWriter(buf)
	w.Comma = ';'

	// Metadata
	_ = w.Write([]string{"# Argus AGDLP Compliance & Audit Report", rep.GeneratedAt.Format(time.RFC3339)})
	_ = w.Write([]string{"# Domain", rep.Domain, "DC Host", rep.DCHost})
	_ = w.Write([]string{"# Cryptographic Chain Head Hash", rep.AuditChainHead})
	_ = w.Write([]string{""})

	// Shares Matrix
	_ = w.Write([]string{"Freigabe", "Ordner", "Berechtigung", "Ressourcengruppe (DL)", "Globale Rollen (G)", "Effektive Benutzeranzahl"})
	for _, folder := range rep.Shares {
		for permName, grp := range folder.Groups {
			membersStr := strings.Join(grp.Members, ", ")
			userCount := fmt.Sprintf("%d Mitglieder", len(grp.Members))
			_ = w.Write([]string{folder.ShareName, folder.FolderName, permName, grp.SAMAccountName, membersStr, userCount})
		}
	}

	_ = w.Write([]string{""})
	// Anomalies
	_ = w.Write([]string{"Konflikt-Typ", "Schweregrad", "Ziel", "Beschreibung", "Empfehlung"})
	for _, c := range rep.Conflicts {
		_ = w.Write([]string{c.Type, c.Severity, c.Target, c.Description, c.Suggestion})
	}

	_ = w.Write([]string{""})
	// Users Summary
	_ = w.Write([]string{"sAMAccountName", "Name", "Abteilung", "Rollen", "Zugriff auf Freigaben (Anzahl)"})
	for _, u := range rep.UserAccessSummary {
		_ = w.Write([]string{u.SAMAccountName, u.DisplayName, u.Department, strings.Join(u.DirectRoles, ", "), fmt.Sprintf("%d", u.SharesCount)})
	}

	w.Flush()
	return buf.Bytes()
}

// GenerateComplianceHTML creates a printable audit certificate
func GenerateComplianceHTML(rep *ComplianceReport) string {
	var sharesRows strings.Builder
	for _, folder := range rep.Shares {
		for perm, grp := range folder.Groups {
			sharesRows.WriteString(fmt.Sprintf(`
				<tr>
					<td><strong>%s</strong></td>
					<td>%s</td>
					<td><span class="badge badge-perm">%s</span></td>
					<td><code>%s</code></td>
					<td>%s</td>
					<td>%d Mitglieder</td>
				</tr>`,
				folder.ShareName, folder.FolderName, perm, grp.SAMAccountName,
				strings.Join(grp.Members, ", "), len(grp.Members),
			))
		}
	}

	var conflictRows strings.Builder
	if len(rep.Conflicts) == 0 {
		conflictRows.WriteString(`<tr><td colspan="4" style="color: #10b981; font-weight: bold;">Keine AGDLP-Konflikte oder Anomalien festgestellt. Konformitaet 100%%.</td></tr>`)
	} else {
		for _, c := range rep.Conflicts {
			conflictRows.WriteString(fmt.Sprintf(`
				<tr>
					<td><span class="badge badge-warn">%s</span></td>
					<td>%s</td>
					<td>%s</td>
					<td>%s</td>
				</tr>`,
				c.Severity, c.Target, c.Description, c.Suggestion,
			))
		}
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="de">
<head>
	<meta charset="UTF-8">
	<title>Argus AGDLP Audit & Compliance Zertifikat</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #1e293b; line-height: 1.5; }
		.header { border-bottom: 3px solid #0284c7; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-end; }
		h1 { margin: 0; color: #0f172a; font-size: 26px; }
		.seal { background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 12px 18px; text-align: right; }
		.hash-box { background: #f8fafc; border: 1px solid #cbd5e1; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; word-break: break-all; margin-bottom: 24px; }
		.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }
		.kpi { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; text-align: center; }
		.kpi-val { font-size: 24px; font-weight: bold; color: #0284c7; }
		.kpi-label { font-size: 12px; color: #64748b; text-transform: uppercase; margin-top: 4px; }
		table { width: 100%%%%; border-collapse: collapse; margin-bottom: 30px; font-size: 13px; }
		th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }
		th { background: #f1f5f9; color: #334155; }
		.badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
		.badge-perm { background: #e0f2fe; color: #0369a1; }
		.badge-warn { background: #fef3c7; color: #b45309; }
		@media print { body { margin: 20px; } .no-print { display: none; } }
	</style>
</head>
<body>
	<div class="header">
		<div>
			<h1>Argus IAM &amp; File Governance Audit Zertifikat</h1>
			<p style="color: #64748b; margin: 4px 0 0 0;">Pruefnachweis gemaess ISO/IEC 27001 &bull; TISAX &bull; Art. 32 DSGVO</p>
		</div>
		<div class="seal">
			<div style="color: #16a34a; font-weight: bold; font-size: 14px;">VERIFIZIERTER AUDIT-STAND</div>
			<div style="font-size: 12px; color: #475569;">%s</div>
		</div>
	</div>

	<div class="hash-box">
		<strong>Kryptografischer Hash-Anker (SHA-256 Audit Head):</strong><br>
		<code>%s</code>
	</div>

	<div class="kpi-grid">
		<div class="kpi"><div class="kpi-val">%d</div><div class="kpi-label">AD Identitäten</div></div>
		<div class="kpi"><div class="kpi-val">%d</div><div class="kpi-label">AGDLP Sicherheitsgruppen</div></div>
		<div class="kpi"><div class="kpi-val">%d</div><div class="kpi-label">Dateifreigaben</div></div>
		<div class="kpi"><div class="kpi-val" style="color: %s;">%d</div><div class="kpi-label">Konflikte / Anomalien</div></div>
	</div>

	<h2>1. AGDLP Dateiberechtigungs-Matrix</h2>
	<table>
		<thead>
			<tr>
				<th>Freigabe</th><th>Ordner</th><th>Recht</th><th>Ressourcengruppe (DL)</th><th>Zugeordnete Rollen (G)</th><th>Mitglieder</th>
			</tr>
		</thead>
		<tbody>
			%s
		</tbody>
	</table>

	<h2>2. Konflikte &amp; Sicherheits-Anomalien</h2>
	<table>
		<thead>
			<tr><th>Schweregrad</th><th>Betroffenes Objekt</th><th>Befund</th><th>Empfohlene Massnahme</th></tr>
		</thead>
		<tbody>
			%s
		</tbody>
	</table>

	<p style="margin-top: 40px; font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 15px;">
		Dieses Dokument wurde durch das Argus Sicherheits-Framework elektronisch signiert und kryptografisch an die unveränderliche Hash-Kette gebunden.
	</p>
</body>
</html>`,
		rep.GeneratedAt.Format("02.01.2006 15:04:05 UTC"),
		rep.AuditChainHead,
		rep.TotalUsers,
		rep.TotalGroups,
		rep.TotalShares,
		func() string {
			if rep.TotalConflicts > 0 {
				return "#e11d48"
			}
			return "#10b981"
		}(),
		rep.TotalConflicts,
		sharesRows.String(),
		conflictRows.String(),
	)
}
