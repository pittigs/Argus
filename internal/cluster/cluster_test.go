package cluster

import (
	"testing"
	"time"
)

func TestClusterPackage(t *testing.T) {
	// 1. Raft
	cm := NewRaftClusterManager("node-1", "127.0.0.1:8080")
	nodes := cm.GetClusterNodes()
	if len(nodes) < 3 {
		t.Fatalf("expected at least 3 cluster nodes")
	}
	leader, err := cm.GetLeader()
	if err != nil || leader.Role != RoleLeader {
		t.Fatalf("expected leader found")
	}

	// 2. Cache
	cache := NewDistributedCache()
	cache.Set("user:123", "active", 1*time.Minute)
	val, ok := cache.Get("user:123")
	if !ok || val != "active" {
		t.Fatalf("expected cache hit")
	}
	invalidated := cache.Invalidate("user:")
	if invalidated != 1 {
		t.Fatalf("expected 1 invalidated key")
	}

	// 3. Storage Tiering
	stm := NewStorageTieringManager()
	st := stm.GetStatus()
	if st.ColdTierRecords == 0 {
		t.Fatalf("expected cold tier records")
	}

	// 4. Replica Router
	rr := NewReplicaRouter()
	reps := rr.ListReplicas()
	if len(reps) < 3 {
		t.Fatalf("expected replicas")
	}
	opt := rr.GetOptimalReplica("eu-central-1")
	if opt.RegionCode != "eu-central-1" {
		t.Fatalf("expected eu-central-1")
	}
}
