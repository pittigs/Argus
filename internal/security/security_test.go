package security

import (
	"testing"
	"time"
)

func TestTOTPService(t *testing.T) {
	totp := NewTOTPService("Argus")
	enrollment, hashedCodes, err := totp.GenerateEnrollment("admin")
	if err != nil {
		t.Fatalf("failed to generate enrollment: %v", err)
	}

	if enrollment.SecretBase32 == "" || len(enrollment.RecoveryCodes) != 8 {
		t.Fatalf("invalid enrollment secret or recovery codes count")
	}
	if len(hashedCodes) != 8 {
		t.Fatalf("invalid hashed recovery codes count")
	}

	code, err := totp.GenerateCode(enrollment.SecretBase32, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %s", code)
	}

	if !totp.ValidateCode(enrollment.SecretBase32, code) {
		t.Fatalf("expected code %s to validate", code)
	}
	if totp.ValidateCode(enrollment.SecretBase32, "999999") && code != "999999" {
		t.Fatalf("expected wrong code to fail")
	}
}

func TestAdaptiveRiskEngine(t *testing.T) {
	engine := NewAdaptiveRiskEngine()

	ctx1 := LoginContext{
		IPAddress: "192.168.1.10",
		UserAgent: "Mozilla/5.0 Chrome",
		Timestamp: time.Now().Add(-20 * time.Minute),
		Geo: GeoCoordinate{
			Latitude:  52.5200,
			Longitude: 13.4050,
			City:      "Berlin",
			Country:   "Germany",
		},
	}
	res1 := engine.AssessLogin("sarah.connor", ctx1)
	if res1.Score > 20 {
		t.Fatalf("expected low score for first normal login, got %d", res1.Score)
	}

	// 20 minutes later login from Tokyo (impossible travel)
	ctx2 := LoginContext{
		IPAddress: "133.1.2.3",
		UserAgent: "Mozilla/5.0 Chrome",
		Timestamp: time.Now(),
		Geo: GeoCoordinate{
			Latitude:  35.6762,
			Longitude: 139.6503,
			City:      "Tokyo",
			Country:   "Japan",
		},
	}
	res2 := engine.AssessLogin("sarah.connor", ctx2)
	if res2.Score < 50 || !res2.RequiresStepUp {
		t.Fatalf("expected high risk for impossible travel, got score %d", res2.Score)
	}
}

func TestPwnedPasswordChecker(t *testing.T) {
	checker := NewPwnedPasswordChecker()

	bad := checker.CheckPassword("admin123")
	if !bad.IsCompromised {
		t.Fatalf("expected admin123 to be marked compromised")
	}

	good := checker.CheckPassword("SuperV3ry$tr0ng-Cryptic-Passphrase-2026!")
	if good.IsCompromised {
		t.Fatalf("expected strong passphrase to not be compromised")
	}
}
