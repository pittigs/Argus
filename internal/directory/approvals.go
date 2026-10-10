package directory

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pittigs/argus/internal/audit"
)

// SensitiveGroups that mandate dual-control (Vier-Augen-Prinzip)
var SensitiveGroups = []string{
	"domain admins", "enterprise admins", "schema admins", "administrators",
	"superadmin", "dl_fs_vorstand_vertraulich_fc", "dl_fs_hr_gehaelter_fc",
}

// RequiresDualApproval returns true if assigning this group requires four-eyes approval
func RequiresDualApproval(groupName string) bool {
	lower := strings.ToLower(groupName)
	for _, sens := range SensitiveGroups {
		if strings.Contains(lower, sens) {
			return true
		}
	}
	return false
}

// CreateApprovalRequest logs a request needing second administrator authorization
func (m *Manager) CreateApprovalRequest(input CreateApprovalInput, actor ActorInfo) (*ApprovalRequest, error) {
	if input.ActionType == "" || input.TargetResource == "" {
		return nil, fmt.Errorf("action_type und target_resource dürfen nicht leer sein")
	}

	id := uuid.New().String()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	_, err := m.db.Exec(`
		INSERT INTO approval_requests (
			id, action_type, target_resource, payload_json,
			requested_by, reason, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
		id, input.ActionType, input.TargetResource, input.PayloadJSON,
		actor.Username, input.Reason, nowStr,
	)
	if err != nil {
		return nil, fmt.Errorf("Fehler beim Anlegen des Genehmigungsantrags: %w", err)
	}

	// Audit log
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "approval.request.created",
		ResourceType:  "approval_request",
		ResourceID:    id,
		Status:        "SUCCESS",
		NewValues:     input.PayloadJSON,
		Reason:        fmt.Sprintf("Vier-Augen-Genehmigung angefordert fuer '%s' auf '%s' (Grund: %s)", input.ActionType, input.TargetResource, input.Reason),
	})

	return &ApprovalRequest{
		ID:             id,
		ActionType:     input.ActionType,
		TargetResource: input.TargetResource,
		PayloadJSON:    input.PayloadJSON,
		RequestedBy:    actor.Username,
		Reason:         input.Reason,
		Status:         "pending",
		CreatedAt:      now,
	}, nil
}

// ListApprovalRequests retrieves approvals with optional status filter
func (m *Manager) ListApprovalRequests(statusFilter string) ([]ApprovalRequest, error) {
	query := `
		SELECT id, action_type, target_resource, payload_json, requested_by,
		       reason, status, approved_by, resolution_notes, created_at, resolved_at
		FROM approval_requests`
	var args []interface{}

	if statusFilter != "" && statusFilter != "all" {
		query += " WHERE status = ?"
		args = append(args, statusFilter)
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("Abfrage fehlgeschlagen: %w", err)
	}
	defer rows.Close()

	var list []ApprovalRequest
	for rows.Next() {
		var item ApprovalRequest
		var crAtStr string
		var appBy, notes, resAtStr sql.NullString

		if err := rows.Scan(
			&item.ID, &item.ActionType, &item.TargetResource, &item.PayloadJSON, &item.RequestedBy,
			&item.Reason, &item.Status, &appBy, &notes, &crAtStr, &resAtStr,
		); err != nil {
			return nil, err
		}

		item.CreatedAt, _ = time.Parse(time.RFC3339, crAtStr)
		if appBy.Valid {
			item.ApprovedBy = appBy.String
		}
		if notes.Valid {
			item.ResolutionNotes = notes.String
		}
		if resAtStr.Valid {
			t, _ := time.Parse(time.RFC3339, resAtStr.String)
			item.ResolvedAt = &t
		}

		list = append(list, item)
	}

	return list, nil
}

// ResolveApprovalRequest approves or rejects a request and executes the payload if approved
func (m *Manager) ResolveApprovalRequest(id string, input ResolveApprovalInput, actor ActorInfo) (*ApprovalRequest, error) {
	decision := strings.ToLower(input.Decision)
	if decision != "approved" && decision != "rejected" {
		return nil, fmt.Errorf("ungueltige Entscheidung: '%s' (erwartet: 'approved' oder 'rejected')", input.Decision)
	}

	var req ApprovalRequest
	var crAtStr string
	var appBy, notes, resAtStr sql.NullString

	err := m.db.QueryRow(`
		SELECT id, action_type, target_resource, payload_json, requested_by,
		       reason, status, approved_by, resolution_notes, created_at, resolved_at
		FROM approval_requests WHERE id = ?`, id).Scan(
		&req.ID, &req.ActionType, &req.TargetResource, &req.PayloadJSON, &req.RequestedBy,
		&req.Reason, &req.Status, &appBy, &notes, &crAtStr, &resAtStr,
	)
	if err != nil {
		return nil, fmt.Errorf("Antrag nicht gefunden: %w", err)
	}

	if req.Status != "pending" {
		return nil, fmt.Errorf("Antrag wurde bereits als '%s' abgeschlossen", req.Status)
	}

	// Vier-Augen-Prinzip: Requester cannot approve their own request!
	if decision == "approved" && strings.EqualFold(req.RequestedBy, actor.Username) {
		return nil, fmt.Errorf("Vier-Augen-Prinzip verletzt: Antragsteller (%s) kann den eigenen Antrag nicht freigeben", actor.Username)
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// If approved, execute the underlying action
	if decision == "approved" {
		if err := m.executeApprovedAction(req, actor); err != nil {
			return nil, fmt.Errorf("Ausfuehrung der genehmigten Aktion fehlgeschlagen: %w", err)
		}
	}

	_, err = m.db.Exec(`
		UPDATE approval_requests
		SET status = ?, approved_by = ?, resolution_notes = ?, resolved_at = ?
		WHERE id = ?`,
		decision, actor.Username, input.Notes, nowStr, id,
	)
	if err != nil {
		return nil, fmt.Errorf("Statusaktualisierung fehlgeschlagen: %w", err)
	}

	// Audit record
	actionStatus := "SUCCESS"
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        fmt.Sprintf("approval.%s", decision),
		ResourceType:  "approval_request",
		ResourceID:    id,
		Status:        actionStatus,
		Reason:        fmt.Sprintf("Vier-Augen-Entscheidung: '%s' durch '%s' (Notizen: %s)", decision, actor.Username, input.Notes),
	})

	req.Status = decision
	req.ApprovedBy = actor.Username
	req.ResolutionNotes = input.Notes
	req.ResolvedAt = &now

	return &req, nil
}

func (m *Manager) executeApprovedAction(req ApprovalRequest, actor ActorInfo) error {
	switch req.ActionType {
	case "ad:membership:grant":
		var p struct {
			GroupName string `json:"group_name"`
			Member    string `json:"member"`
		}
		if err := json.Unmarshal([]byte(req.PayloadJSON), &p); err != nil {
			return err
		}
		return m.AddMemberToGroup(p.GroupName, p.Member, actor)

	case "ad:user:delete":
		var p struct {
			SAMAccountName string `json:"sam_account_name"`
		}
		if err := json.Unmarshal([]byte(req.PayloadJSON), &p); err != nil {
			return err
		}
		return m.DeleteUser(p.SAMAccountName, actor)

	default:
		// Default success if non-executable or generic
		return nil
	}
}
