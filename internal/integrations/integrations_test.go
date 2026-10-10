package integrations

import (
	"testing"
	"time"
)

func TestIntegrationsPackage(t *testing.T) {
	// 1. Terraform
	tf := GenerateTerraformHCL([]string{"sarah.connor"}, []string{"SuperAdmin"}, []string{"Finance"})
	if tf.HCLCode == "" {
		t.Fatalf("expected non-empty HCL code")
	}

	// 2. SCIM 2.0
	scim := NewSCIMServer()
	list := scim.ListUsers()
	if list.TotalResults == 0 {
		t.Fatalf("expected SCIM users")
	}

	// 3. Webhooks
	we := NewWebhookEngine()
	subs := we.ListSubscriptions()
	if len(subs) == 0 {
		t.Fatalf("expected subscriptions")
	}
	res, err := we.DispatchMock("wh-sec-alert", WebhookPayload{
		EventID:   "evt-1",
		EventType: "audit.critical",
		Timestamp: time.Now(),
		Data:      map[string]string{"alert": "test"},
	})
	if err != nil || res == "" {
		t.Fatalf("dispatch failed: %v", err)
	}

	// 4. OpenAPI
	spec := GenerateOpenAPISpec()
	if spec["openapi"] != "3.1.0" {
		t.Fatalf("expected openapi 3.1.0")
	}
}
