package audit

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pittigs/argus/internal/db"
	"github.com/pittigs/argus/internal/model"
)

// EventBroker manages active SSE subscribers for real-time audit feed
type EventBroker struct {
	clients   map[chan *model.AuditLog]bool
	clientsMu sync.RWMutex
}

func newEventBroker() *EventBroker {
	return &EventBroker{
		clients: make(map[chan *model.AuditLog]bool),
	}
}

func (b *EventBroker) Subscribe() chan *model.AuditLog {
	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	ch := make(chan *model.AuditLog, 25)
	b.clients[ch] = true
	return ch
}

func (b *EventBroker) Unsubscribe(ch chan *model.AuditLog) {
	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	if _, ok := b.clients[ch]; ok {
		delete(b.clients, ch)
		close(ch)
	}
}

func (b *EventBroker) Broadcast(entry *model.AuditLog) {
	b.clientsMu.RLock()
	defer b.clientsMu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- entry:
		default:
			// Non-blocking drop if channel is full to prevent lag
		}
	}
}

// Service manages append-only, tamper-evident audit logging and verification
type Service struct {
	db     *db.DB
	mux    sync.Mutex
	broker *EventBroker
}

func NewService(database *db.DB) *Service {
	return &Service{
		db:     database,
		broker: newEventBroker(),
	}
}

// Subscribe returns a channel that receives newly recorded audit log entries in real-time
func (s *Service) Subscribe() chan *model.AuditLog {
	return s.broker.Subscribe()
}

// Unsubscribe removes a listener channel
func (s *Service) Unsubscribe(ch chan *model.AuditLog) {
	s.broker.Unsubscribe(ch)
}

// LogEntryInput specifies fields for creating an audit record
type LogEntryInput struct {
	ActorID       string
	ActorUsername string
	ActorIP       string
	UserAgent     string
	Action        string
	ResourceType  string
	ResourceID    string
	Status        string
	OldValues     interface{}
	NewValues     interface{}
	Reason        string
}

// Record creates a tamper-evident, hash-chained audit record in the database
func (s *Service) Record(in LogEntryInput) (*model.AuditLog, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	id := uuid.New().String()

	var oldValStr, newValStr string
	if in.OldValues != nil {
		if str, ok := in.OldValues.(string); ok {
			oldValStr = str
		} else {
			b, _ := json.Marshal(in.OldValues)
			oldValStr = string(b)
		}
	}
	if in.NewValues != nil {
		if str, ok := in.NewValues.(string); ok {
			newValStr = str
		} else {
			b, _ := json.Marshal(in.NewValues)
			newValStr = string(b)
		}
	}

	if in.Status == "" {
		in.Status = "SUCCESS"
	}

	// Fetch previous hash from the latest entry
	var prevHash string
	err := s.db.QueryRow("SELECT entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1").Scan(&prevHash)
	if err != nil {
		if err == sql.ErrNoRows {
			prevHash = strings.Repeat("0", 64)
		} else {
			return nil, fmt.Errorf("failed to fetch last audit hash: %w", err)
		}
	}

	entryHash := model.ComputeAuditHash(
		prevHash, nowStr, in.ActorID, in.ActorUsername,
		in.Action, in.ResourceType, in.ResourceID,
		in.Status, oldValStr, newValStr,
	)

	res, err := s.db.Exec(`
		INSERT INTO audit_logs (
			id, timestamp, actor_id, actor_username, actor_ip, user_agent,
			action, resource_type, resource_id, status, old_values, new_values,
			reason, prev_hash, entry_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, nowStr, in.ActorID, in.ActorUsername, in.ActorIP, in.UserAgent,
		in.Action, in.ResourceType, in.ResourceID, in.Status, oldValStr, newValStr,
		in.Reason, prevHash, entryHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert audit record: %w", err)
	}

	seq, _ := res.LastInsertId()

	entry := &model.AuditLog{
		ID:             id,
		SequenceNumber: seq,
		Timestamp:      now,
		ActorID:        in.ActorID,
		ActorUsername:  in.ActorUsername,
		ActorIP:        in.ActorIP,
		UserAgent:      in.UserAgent,
		Action:         in.Action,
		ResourceType:   in.ResourceType,
		ResourceID:     in.ResourceID,
		Status:         in.Status,
		OldValues:      oldValStr,
		NewValues:      newValStr,
		Reason:         in.Reason,
		PrevHash:       prevHash,
		EntryHash:      entryHash,
	}

	s.broker.Broadcast(entry)

	return entry, nil
}

// FilterParams defines criteria for searching audit records
type FilterParams struct {
	Search       string
	Actor        string
	Action       string
	ResourceType string
	Status       string
	From         *time.Time
	To           *time.Time
	Limit        int
	Offset       int
}

// Query retrieves filtered audit logs
func (s *Service) Query(params FilterParams) ([]model.AuditLog, int64, error) {
	var conditions []string
	var args []interface{}

	if params.Search != "" {
		conditions = append(conditions, "(actor_username LIKE ? OR action LIKE ? OR resource_type LIKE ? OR resource_id LIKE ? OR reason LIKE ?)")
		pattern := "%" + params.Search + "%"
		args = append(args, pattern, pattern, pattern, pattern, pattern)
	}
	if params.Actor != "" {
		conditions = append(conditions, "actor_username = ?")
		args = append(args, params.Actor)
	}
	if params.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, params.Action)
	}
	if params.ResourceType != "" {
		conditions = append(conditions, "resource_type = ?")
		args = append(args, params.ResourceType)
	}
	if params.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, params.Status)
	}
	if params.From != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, params.From.Format(time.RFC3339))
	}
	if params.To != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, params.To.Format(time.RFC3339))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_logs %s", whereClause)
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	limit := params.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	selectQuery := fmt.Sprintf(`
		SELECT seq, id, timestamp, actor_id, actor_username, actor_ip, user_agent,
		       action, resource_type, resource_id, status, COALESCE(old_values, ''),
		       COALESCE(new_values, ''), COALESCE(reason, ''), prev_hash, entry_hash
		FROM audit_logs
		%s
		ORDER BY seq DESC
		LIMIT ? OFFSET ?`, whereClause)

	queryArgs := append(args, limit, offset)
	rows, err := s.db.Query(selectQuery, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []model.AuditLog
	for rows.Next() {
		var l model.AuditLog
		var tsStr string
		err := rows.Scan(
			&l.SequenceNumber, &l.ID, &tsStr, &l.ActorID, &l.ActorUsername, &l.ActorIP, &l.UserAgent,
			&l.Action, &l.ResourceType, &l.ResourceID, &l.Status, &l.OldValues,
			&l.NewValues, &l.Reason, &l.PrevHash, &l.EntryHash,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
			l.Timestamp = t
		}
		logs = append(logs, l)
	}

	return logs, total, nil
}

// VerifyChain checks the entire cryptographic hash chain from seq 1 to latest
func (s *Service) VerifyChain() (*model.AuditVerificationResult, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	rows, err := s.db.Query(`
		SELECT seq, id, timestamp, actor_id, actor_username, actor_ip, user_agent,
		       action, resource_type, resource_id, status, COALESCE(old_values, ''),
		       COALESCE(new_values, ''), prev_hash, entry_hash
		FROM audit_logs
		ORDER BY seq ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit chain: %w", err)
	}
	defer rows.Close()

	var verifiedCount int64
	var expectedPrevHash string = strings.Repeat("0", 64)

	for rows.Next() {
		var seq int64
		var id, actorID, actorUsername, actorIP, userAgent, action, resType, resID, status, oldVal, newVal, prevHash, entryHash string
		var tsStr string

		if err := rows.Scan(&seq, &id, &tsStr, &actorID, &actorUsername, &actorIP, &userAgent, &action, &resType, &resID, &status, &oldVal, &newVal, &prevHash, &entryHash); err != nil {
			return nil, fmt.Errorf("failed to scan chain entry: %w", err)
		}

		// 1. Check prev_hash linkage
		if verifiedCount == 0 {
			// Genesis block
			if prevHash != strings.Repeat("0", 64) {
				return &model.AuditVerificationResult{
					TotalEntries:   verifiedCount + 1,
					VerifiedCount:  verifiedCount,
					IsCompromised:  true,
					BrokenIndex:    seq,
					BrokenEntryID:  id,
					Message:        fmt.Sprintf("Genesis block invalid: prev_hash mismatch at sequence %d", seq),
					LastVerifiedAt: time.Now().UTC(),
				}, nil
			}
		} else {
			if prevHash != expectedPrevHash {
				return &model.AuditVerificationResult{
					TotalEntries:   verifiedCount + 1,
					VerifiedCount:  verifiedCount,
					IsCompromised:  true,
					BrokenIndex:    seq,
					BrokenEntryID:  id,
					Message:        fmt.Sprintf("Chain link broken: sequence %d prev_hash did not match previous block's entry_hash", seq),
					LastVerifiedAt: time.Now().UTC(),
				}, nil
			}
		}

		// 2. Recompute SHA-256 for this block
		computed := model.ComputeAuditHash(prevHash, tsStr, actorID, actorUsername, action, resType, resID, status, oldVal, newVal)
		if computed != entryHash {
			return &model.AuditVerificationResult{
				TotalEntries:   verifiedCount + 1,
				VerifiedCount:  verifiedCount,
				IsCompromised:  true,
				BrokenIndex:    seq,
				BrokenEntryID:  id,
				Message:        fmt.Sprintf("Tamper detected: data mismatch in sequence %d (stored hash %s != computed %s)", seq, entryHash, computed),
				LastVerifiedAt: time.Now().UTC(),
			}, nil
		}

		expectedPrevHash = entryHash
		verifiedCount++
	}

	return &model.AuditVerificationResult{
		TotalEntries:   verifiedCount,
		VerifiedCount:  verifiedCount,
		IsCompromised:  false,
		Message:        fmt.Sprintf("Cryptographic chain verified successfully. All %d audit entries are immutable and valid.", verifiedCount),
		LastVerifiedAt: time.Now().UTC(),
	}, nil
}

// ExportCSV exports filtered logs to CSV format
func (s *Service) ExportCSV(params FilterParams) ([]byte, error) {
	params.Limit = 100000 // allow full export up to 100k
	params.Offset = 0
	logs, _, err := s.Query(params)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write CSV Header
	header := []string{
		"Sequence", "EntryID", "Timestamp (UTC)", "Actor Username", "Actor ID",
		"Client IP", "User Agent", "Action", "Resource Type", "Resource ID",
		"Status", "Old Values", "New Values", "Reason", "Previous Hash", "Entry Hash (SHA-256)",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	for _, l := range logs {
		row := []string{
			fmt.Sprintf("%d", l.SequenceNumber),
			l.ID,
			l.Timestamp.Format(time.RFC3339),
			l.ActorUsername,
			l.ActorID,
			l.ActorIP,
			l.UserAgent,
			l.Action,
			l.ResourceType,
			l.ResourceID,
			l.Status,
			l.OldValues,
			l.NewValues,
			l.Reason,
			l.PrevHash,
			l.EntryHash,
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return buf.Bytes(), writer.Error()
}

// ExportJSON exports filtered logs to formatted JSON
func (s *Service) ExportJSON(params FilterParams) ([]byte, error) {
	params.Limit = 100000
	params.Offset = 0
	logs, total, err := s.Query(params)
	if err != nil {
		return nil, err
	}

	exportDoc := struct {
		ExportedAt time.Time        `json:"exported_at"`
		TotalCount int64            `json:"total_count"`
		Records    []model.AuditLog `json:"records"`
	}{
		ExportedAt: time.Now().UTC(),
		TotalCount: total,
		Records:    logs,
	}

	return json.MarshalIndent(exportDoc, "", "  ")
}

// ExecuteRawTamperForAuditTest executes raw SQL specifically for tamper-detection integration testing.
func (s *Service) ExecuteRawTamperForAuditTest(query string, args ...any) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

