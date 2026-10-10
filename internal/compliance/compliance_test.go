package compliance

import (
	"testing"
	"time"
)

func TestCompliancePackage(t *testing.T) {
	// 1. Framework Mapper
	mapper := NewFrameworkMapper()
	iso := mapper.ListControls("ISO_27001")
	if len(iso) == 0 {
		t.Fatalf("expected ISO 27001 controls")
	}

	// 2. Time-Travel Engine
	tte := NewTimeTravelEngine()
	t0 := time.Now().Add(-2 * time.Hour)
	t1 := time.Now().Add(-1 * time.Hour)
	t2 := time.Now()

	tte.AddEvent(TimeTravelEvent{Timestamp: t0, Action: "membership.add", Username: "user1", GroupName: "G_Dev"})
	tte.AddEvent(TimeTravelEvent{Timestamp: t1, Action: "membership.add", Username: "user1", GroupName: "Domain Admins"})
	tte.AddEvent(TimeTravelEvent{Timestamp: t2, Action: "membership.remove", Username: "user1", GroupName: "Domain Admins"})

	// At 90 minutes ago, user1 had G_Dev but NOT Domain Admins yet
	statePast := tte.ReconstructStateAt(t0.Add(30 * time.Minute))
	groupsPast := statePast.UserStates["user1"]
	if len(groupsPast) != 1 || groupsPast[0] != "G_Dev" {
		t.Fatalf("expected only G_Dev at past time, got %v", groupsPast)
	}

	// 3. SIEM Exporter
	se := NewSIEMExporter("https://siem.corp.local:8088")
	msg := SIEMMessage{
		Facility:  4,
		Severity:  6,
		Timestamp: time.Now(),
		Hostname:  "argus-server",
		AppName:   "argus-iam",
		ProcID:    "1234",
		MsgID:     "AUTH_LOGIN_SUCCESS",
		Message:   "User sarah.connor successfully logged in",
		StructuredData: map[string]string{
			"username": "sarah.connor",
			"ip":       "10.0.0.1",
		},
	}
	syslog := se.FormatRFC5424(msg)
	if syslog == "" {
		t.Fatalf("empty syslog message")
	}
	ecs, err := se.FormatECS(msg)
	if err != nil || ecs == "" {
		t.Fatalf("failed ecs formatting: %v", err)
	}

	// 4. GDPR Shredder
	shredder := NewGDPRShredder()
	shredder.RegisterUserKey("user-123")
	rec, err := shredder.ShredUser("john.doe", "user-123")
	if err != nil || rec.PseudonymID == "" {
		t.Fatalf("failed to shred user: %v", err)
	}
	if !shredder.IsShredded("user-123") {
		t.Fatalf("expected user to be marked shredded")
	}

	// 5. Compliance Certificate
	cert := GenerateComplianceCertificate("auditor", "headhash123", 5)
	if cert.DigitalSeal == "" || cert.ComplianceScore != 100 {
		t.Fatalf("invalid certificate generated")
	}
}
