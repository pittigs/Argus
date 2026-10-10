package directory

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pittigs/argus/internal/audit"
)

// CreateTemporaryMembership assigns a user to an AGDLP or security group for a finite duration
func (m *Manager) CreateTemporaryMembership(req CreateJITRequest, actor ActorInfo) (*TemporaryMembership, error) {
	if req.UserSAM == "" || req.GroupName == "" {
		return nil, fmt.Errorf("user_sam und group_name dürfen nicht leer sein")
	}
	if req.DurationHours <= 0 {
		req.DurationHours = 1 // Default 1 hour
	}
	if req.DurationHours > 720 { // Max 30 days
		return nil, fmt.Errorf("maximale JIT-Laufzeit beträgt 720 Stunden (30 Tage)")
	}

	// Verify target group exists
	grp, err := m.activeProvider().GetGroup(req.GroupName)
	if err != nil || grp == nil {
		return nil, fmt.Errorf("Zielgruppe '%s' nicht im Verzeichnis gefunden", req.GroupName)
	}

	// Verify user exists
	usr, err := m.activeProvider().GetUser(req.UserSAM)
	if err != nil || usr == nil {
		return nil, fmt.Errorf("Benutzer '%s' nicht im Verzeichnis gefunden", req.UserSAM)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(req.DurationHours) * time.Hour)
	nowStr := now.Format(time.RFC3339)
	expStr := expiresAt.Format(time.RFC3339)
	id := uuid.New().String()

	// Assign group membership in AD/Mock provider
	if err := m.AddMemberToGroup(req.GroupName, req.UserSAM, actor); err != nil {
		return nil, fmt.Errorf("Zuweisung zur Gruppe im AD fehlgeschlagen: %w", err)
	}

	_, err = m.db.Exec(`
		INSERT INTO temporary_memberships (
			id, user_sam, group_name, requested_by, reason,
			duration_hours, status, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
		id, req.UserSAM, req.GroupName, actor.Username, req.Reason,
		req.DurationHours, nowStr, expStr,
	)
	if err != nil {
		return nil, fmt.Errorf("DB-Speicherung fehlgeschlagen: %w", err)
	}

	// Audit record
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.jit.grant",
		ResourceType:  "temporary_membership",
		ResourceID:    id,
		Status:        "SUCCESS",
		NewValues:     fmt.Sprintf(`{"user_sam":"%s","group_name":"%s","duration_hours":%d,"expires_at":"%s"}`, req.UserSAM, req.GroupName, req.DurationHours, expStr),
		Reason:        fmt.Sprintf("Befristeter JIT-Zugriff gewährt: '%s' in Gruppe '%s' fuer %d Std. (Grund: %s)", req.UserSAM, req.GroupName, req.DurationHours, req.Reason),
	})

	return &TemporaryMembership{
		ID:            id,
		UserSAM:       req.UserSAM,
		GroupName:     req.GroupName,
		RequestedBy:   actor.Username,
		Reason:        req.Reason,
		DurationHours: req.DurationHours,
		Status:        "active",
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
	}, nil
}

// ListActiveTemporaryMemberships returns active time-bound assignments
func (m *Manager) ListActiveTemporaryMemberships() ([]TemporaryMembership, error) {
	rows, err := m.db.Query(`
		SELECT id, user_sam, group_name, requested_by, reason, duration_hours,
		       status, created_at, expires_at, revoked_at, revoked_by
		FROM temporary_memberships
		ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("Abfrage fehlgeschlagen: %w", err)
	}
	defer rows.Close()

	var list []TemporaryMembership
	for rows.Next() {
		var item TemporaryMembership
		var crAtStr, expAtStr string
		var revAtStr, revBy sql.NullString

		if err := rows.Scan(
			&item.ID, &item.UserSAM, &item.GroupName, &item.RequestedBy, &item.Reason,
			&item.DurationHours, &item.Status, &crAtStr, &expAtStr, &revAtStr, &revBy,
		); err != nil {
			return nil, err
		}

		item.CreatedAt, _ = time.Parse(time.RFC3339, crAtStr)
		item.ExpiresAt, _ = time.Parse(time.RFC3339, expAtStr)
		if revAtStr.Valid {
			t, _ := time.Parse(time.RFC3339, revAtStr.String)
			item.RevokedAt = &t
		}
		if revBy.Valid {
			item.RevokedBy = revBy.String
		}

		list = append(list, item)
	}

	return list, nil
}

// RevokeTemporaryMembership manually revokes a temporary access before expiration
func (m *Manager) RevokeTemporaryMembership(id string, actor ActorInfo) error {
	var userSAM, groupName, status string
	err := m.db.QueryRow("SELECT user_sam, group_name, status FROM temporary_memberships WHERE id = ?", id).Scan(&userSAM, &groupName, &status)
	if err != nil {
		return fmt.Errorf("JIT-Eintrag nicht gefunden: %w", err)
	}

	if status != "active" {
		return fmt.Errorf("JIT-Eintrag ist bereits %s", status)
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// Remove from group
	_ = m.RemoveMemberFromGroup(groupName, userSAM, actor)

	_, err = m.db.Exec(`
		UPDATE temporary_memberships
		SET status = 'revoked', revoked_at = ?, revoked_by = ?
		WHERE id = ?`,
		nowStr, actor.Username, id,
	)
	if err != nil {
		return fmt.Errorf("Statusaktualisierung fehlgeschlagen: %w", err)
	}

	// Audit record
	_, _ = m.audit.Record(audit.LogEntryInput{
		ActorID:       actor.ID,
		ActorUsername: actor.Username,
		ActorIP:       actor.IPAddress,
		UserAgent:     actor.UserAgent,
		Action:        "ad.jit.revoked",
		ResourceType:  "temporary_membership",
		ResourceID:    id,
		Status:        "SUCCESS",
		Reason:        fmt.Sprintf("Befristeter JIT-Zugriff vorzeitig durch Administrator '%s' widerrufen: '%s' aus '%s'", actor.Username, userSAM, groupName),
	})

	return nil
}

// CheckAndRevokeExpired checks for expired temporary memberships and revokes them automatically
func (m *Manager) CheckAndRevokeExpired() (int, error) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	rows, err := m.db.Query(`
		SELECT id, user_sam, group_name
		FROM temporary_memberships
		WHERE status = 'active' AND expires_at <= ?`,
		nowStr,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type expItem struct {
		id, userSAM, groupName string
	}
	var expired []expItem
	for rows.Next() {
		var item expItem
		if err := rows.Scan(&item.id, &item.userSAM, &item.groupName); err == nil {
			expired = append(expired, item)
		}
	}

	sysActor := ActorInfo{
		ID:        "system",
		Username:  "argus-jit-daemon",
		IPAddress: "127.0.0.1",
		UserAgent: "Argus JIT Daemon/1.0",
	}

	revokedCount := 0
	for _, item := range expired {
		// Remove group membership
		_ = m.RemoveMemberFromGroup(item.groupName, item.userSAM, sysActor)

		_, _ = m.db.Exec(`
			UPDATE temporary_memberships
			SET status = 'expired', revoked_at = ?, revoked_by = 'system'
			WHERE id = ?`,
			nowStr, item.id,
		)

		// Audit record
		_, _ = m.audit.Record(audit.LogEntryInput{
			ActorID:       sysActor.ID,
			ActorUsername: sysActor.Username,
			ActorIP:       sysActor.IPAddress,
			UserAgent:     sysActor.UserAgent,
			Action:        "ad.jit.expired",
			ResourceType:  "temporary_membership",
			ResourceID:    item.id,
			Status:        "SUCCESS",
			Reason:        fmt.Sprintf("Befristeter Zugriff abgelaufen: Mitglied '%s' automatisch aus Gruppe '%s' entfernt", item.userSAM, item.groupName),
		})

		revokedCount++
	}

	return revokedCount, nil
}

// StartJITWorker launches background daemon checking for expired memberships
func (m *Manager) StartJITWorker(interval time.Duration, stopChan <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_, _ = m.CheckAndRevokeExpired()
			case <-stopChan:
				return
			}
		}
	}()
}
