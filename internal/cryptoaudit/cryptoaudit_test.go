package cryptoaudit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMerkleTreeAndProofs(t *testing.T) {
	hashes := []string{
		"a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
		"b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01",
		"c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef012",
	}

	tree := BuildMerkleTree(hashes)
	if tree.Root == nil || tree.Root.Hash == "" {
		t.Fatalf("expected non-empty root hash")
	}

	proof, err := tree.GenerateProof(hashes[1])
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	if !VerifyMerkleProof(proof) {
		t.Fatalf("expected merkle proof to verify")
	}

	// Corrupt proof
	proof.Path[0] = "0000000000000000000000000000000000000000000000000000000000000000"
	if VerifyMerkleProof(proof) {
		t.Fatalf("expected corrupted merkle proof to fail verification")
	}
}

func TestBlockSignerAndPQC(t *testing.T) {
	signer, err := NewBlockSigner()
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sig, err := signer.SignHash(hash)
	if err != nil {
		t.Fatalf("failed to sign hash: %v", err)
	}

	if !signer.VerifySignature(hash, sig) {
		t.Fatalf("signature verification failed")
	}

	pqc, err := signer.SignPQCHybrid(hash)
	if err != nil {
		t.Fatalf("failed to sign pqc: %v", err)
	}
	if pqc.ClassicSigHex == "" || pqc.PQCSigHex == "" {
		t.Fatalf("empty pqc signatures")
	}
}

func TestWORMAndEnvelopeEncryption(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "argus_worm_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	worm, err := NewWORMStorage(filepath.Join(tmpDir, "ledger"))
	if err != nil {
		t.Fatal(err)
	}

	rec := WORMRecord{
		SequenceNumber: 1,
		EntryHash:      "abc123",
		PrevHash:       "000000",
		Timestamp:      time.Now(),
		PayloadDigest:  "digest",
		Signature:      "sig",
	}
	if err := worm.AppendImmutable(rec); err != nil {
		t.Fatal(err)
	}

	count, err := worm.CountRecords()
	if err != nil || count != 1 {
		t.Fatalf("expected count 1, got %d, err %v", count, err)
	}

	enc, err := NewEnvelopeEncryption()
	if err != nil {
		t.Fatal(err)
	}

	secret := "Confidential Personnel Data: Max Mustermann SSN 123-45-678"
	field, err := enc.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := enc.Decrypt(field)
	if err != nil || decrypted != secret {
		t.Fatalf("decrypt mismatch: got %s, want %s", decrypted, secret)
	}
}
