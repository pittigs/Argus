package adextended

import (
	"testing"
)

func TestADExtendedFeatures(t *testing.T) {
	// 1. MultiForest
	mf := NewMultiForestManager()
	domains := mf.ListDomains()
	if len(domains) < 2 {
		t.Fatalf("expected at least 2 domains, got %d", len(domains))
	}
	if err := mf.SwitchActiveDomain("emea.corp.local"); err != nil {
		t.Fatalf("failed to switch domain: %v", err)
	}
	if mf.GetActiveDomain() != "emea.corp.local" {
		t.Fatalf("expected emea.corp.local active")
	}

	// 2. PSO
	pso := NewPSOManager()
	list := pso.ListPSOs()
	if len(list) < 2 {
		t.Fatalf("expected at least 2 PSOs")
	}

	// 3. gMSA
	gmsa := NewGMSAManager()
	accounts := gmsa.ListGMSAs()
	if len(accounts) == 0 {
		t.Fatalf("expected gMSA accounts")
	}
	if err := gmsa.RotatePasswordNow("gmsa-argus-svc$"); err != nil {
		t.Fatalf("failed to rotate gMSA password: %v", err)
	}

	// 4. Recycle Bin
	rb := NewRecycleBinManager()
	delObjs := rb.ListDeletedObjects()
	if len(delObjs) == 0 {
		t.Fatalf("expected deleted objects in recycle bin")
	}
	restored, err := rb.RestoreObject(delObjs[0].ObjectGUID)
	if err != nil || restored == nil {
		t.Fatalf("failed to restore object: %v", err)
	}

	// 5. Delta Sync
	ds := NewDeltaSyncEngine("corp.local")
	st := ds.GetStatus()
	if st.SyncState != "IN_SYNC" {
		t.Fatalf("expected IN_SYNC status")
	}
	ds.RecordExternalChange(1048600)
	st2 := ds.GetStatus()
	if st2.HighestUSN != 1048600 {
		t.Fatalf("expected updated USN")
	}
}
