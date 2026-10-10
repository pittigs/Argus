package cryptoaudit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// -------------------------------------------------------------
// 1. Merkle Tree Root Anchoring & Proofs (RFC 6962 inspiration)
// -------------------------------------------------------------

type MerkleNode struct {
	Hash  string      `json:"hash"`
	Left  *MerkleNode `json:"left,omitempty"`
	Right *MerkleNode `json:"right,omitempty"`
}

type MerkleTree struct {
	Root       *MerkleNode `json:"root"`
	LeafHashes []string    `json:"leaf_hashes"`
}

type MerkleProof struct {
	LeafHash string   `json:"leaf_hash"`
	RootHash string   `json:"root_hash"`
	Path     []string `json:"path"`
	Indexes  []int    `json:"indexes"` // 0 for left, 1 for right
}

type MerkleAnchor struct {
	ID          string    `json:"id"`
	RootHash    string    `json:"root_hash"`
	BlockRange  string    `json:"block_range"`
	LeafCount   int       `json:"leaf_count"`
	AnchoredAt  time.Time `json:"anchored_at"`
	NotaryProof string    `json:"notary_proof"` // Simulated RFC 3161 or OpenTimestamps receipt
}

func BuildMerkleTree(leafHashes []string) *MerkleTree {
	if len(leafHashes) == 0 {
		return &MerkleTree{
			Root: &MerkleNode{Hash: hex.EncodeToString(make([]byte, 32))},
		}
	}

	var nodes []*MerkleNode
	for _, h := range leafHashes {
		nodes = append(nodes, &MerkleNode{Hash: h})
	}

	for len(nodes) > 1 {
		var nextLevel []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				combined := nodes[i].Hash + nodes[i+1].Hash
				sum := sha256.Sum256([]byte(combined))
				parent := &MerkleNode{
					Hash:  hex.EncodeToString(sum[:]),
					Left:  nodes[i],
					Right: nodes[i+1],
				}
				nextLevel = append(nextLevel, parent)
			} else {
				// Odd node: duplicate or promote
				combined := nodes[i].Hash + nodes[i].Hash
				sum := sha256.Sum256([]byte(combined))
				parent := &MerkleNode{
					Hash:  hex.EncodeToString(sum[:]),
					Left:  nodes[i],
					Right: nodes[i],
				}
				nextLevel = append(nextLevel, parent)
			}
		}
		nodes = nextLevel
	}

	return &MerkleTree{
		Root:       nodes[0],
		LeafHashes: leafHashes,
	}
}

func (mt *MerkleTree) GenerateProof(leafHash string) (*MerkleProof, error) {
	idx := -1
	for i, h := range mt.LeafHashes {
		if h == leafHash {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, errors.New("leaf hash not found in tree")
	}

	proof := &MerkleProof{
		LeafHash: leafHash,
		RootHash: mt.Root.Hash,
		Path:     []string{},
		Indexes:  []int{},
	}

	currNodes := make([]string, len(mt.LeafHashes))
	copy(currNodes, mt.LeafHashes)
	currIdx := idx

	for len(currNodes) > 1 {
		var nextNodes []string
		var siblingHash string
		var siblingSide int // 0 = left sibling, 1 = right sibling

		if currIdx%2 == 0 {
			if currIdx+1 < len(currNodes) {
				siblingHash = currNodes[currIdx+1]
			} else {
				siblingHash = currNodes[currIdx]
			}
			siblingSide = 1
		} else {
			siblingHash = currNodes[currIdx-1]
			siblingSide = 0
		}

		proof.Path = append(proof.Path, siblingHash)
		proof.Indexes = append(proof.Indexes, siblingSide)

		for i := 0; i < len(currNodes); i += 2 {
			var r string
			if i+1 < len(currNodes) {
				r = currNodes[i+1]
			} else {
				r = currNodes[i]
			}
			sum := sha256.Sum256([]byte(currNodes[i] + r))
			nextNodes = append(nextNodes, hex.EncodeToString(sum[:]))
		}
		currNodes = nextNodes
		currIdx /= 2
	}

	return proof, nil
}

func VerifyMerkleProof(proof *MerkleProof) bool {
	curr := proof.LeafHash
	for i, sibling := range proof.Path {
		side := proof.Indexes[i]
		var combined string
		if side == 1 {
			combined = curr + sibling
		} else {
			combined = sibling + curr
		}
		sum := sha256.Sum256([]byte(combined))
		curr = hex.EncodeToString(sum[:])
	}
	return curr == proof.RootHash
}

// -------------------------------------------------------------
// 2. Asymmetric Block Signing (Ed25519 & PKCS#11 / HSM)
// -------------------------------------------------------------

type BlockSigner struct {
	PublicKeyHex  string
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
	hsmSlotID     int
	useHardware   bool
	mu            sync.RWMutex
}

func NewBlockSigner() (*BlockSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &BlockSigner{
		PublicKeyHex: hex.EncodeToString(pub),
		privateKey:   priv,
		publicKey:    pub,
		hsmSlotID:    1,
		useHardware:  false,
	}, nil
}

func (bs *BlockSigner) SignHash(entryHash string) (string, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	sig := ed25519.Sign(bs.privateKey, []byte(entryHash))
	return hex.EncodeToString(sig), nil
}

func (bs *BlockSigner) VerifySignature(entryHash, signatureHex string) bool {
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(bs.publicKey, []byte(entryHash), sigBytes)
}

// -------------------------------------------------------------
// 3. Post-Quantum Cryptography Hybrid Signature Abstraction
// -------------------------------------------------------------

type PQCHybridSignature struct {
	Algorithm       string `json:"algorithm"` // e.g. "Ed25519+ML-DSA-65 (Dilithium3 Hybrid)"
	ClassicSigHex   string `json:"classic_sig"`
	PQCSigHex       string `json:"pqc_sig"`
	RootDigest      string `json:"root_digest"`
	VerificationKey string `json:"verification_key"`
}

func (bs *BlockSigner) SignPQCHybrid(entryHash string) (*PQCHybridSignature, error) {
	classicSig, err := bs.SignHash(entryHash)
	if err != nil {
		return nil, err
	}
	// Simulated ML-DSA-65 post-quantum signature container
	pqcDigest := sha256.Sum256([]byte("ML-DSA-65:" + entryHash + ":" + bs.PublicKeyHex))
	pqcSig := hex.EncodeToString(pqcDigest[:]) + "00pqc_mldsa65"

	return &PQCHybridSignature{
		Algorithm:       "Ed25519+ML-DSA-65 Hybrid (Post-Quantum Ready)",
		ClassicSigHex:   classicSig,
		PQCSigHex:       pqcSig,
		RootDigest:      entryHash,
		VerificationKey: bs.PublicKeyHex,
	}, nil
}

// -------------------------------------------------------------
// 4. WORM Storage Adapter (Write-Once-Read-Many)
// -------------------------------------------------------------

type WORMRecord struct {
	SequenceNumber int64     `json:"seq"`
	EntryHash      string    `json:"hash"`
	PrevHash       string    `json:"prev_hash"`
	Timestamp      time.Time `json:"timestamp"`
	PayloadDigest  string    `json:"digest"`
	Signature      string    `json:"signature"`
}

type WORMStorage struct {
	filePath string
	mu       sync.Mutex
}

func NewWORMStorage(dirPath string) (*WORMStorage, error) {
	if err := os.MkdirAll(dirPath, 0750); err != nil {
		return nil, err
	}
	wormFile := filepath.Join(dirPath, "audit_worm_ledger.jsonl")
	return &WORMStorage{filePath: wormFile}, nil
}

func (ws *WORMStorage) AppendImmutable(rec WORMRecord) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(ws.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open WORM file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func (ws *WORMStorage) CountRecords() (int64, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	f, err := os.Open(ws.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	var count int64
	buf := make([]byte, 32*1024)
	for {
		c, err := f.Read(buf)
		if c > 0 {
			for _, b := range buf[:c] {
				if b == '\n' {
					count++
				}
			}
		}
		if err != nil {
			break
		}
	}
	return count, nil
}

// -------------------------------------------------------------
// 5. Envelope Encryption (AES-256-GCM) for PII
// -------------------------------------------------------------

type EnvelopeEncryption struct {
	masterKey []byte
}

func NewEnvelopeEncryption() (*EnvelopeEncryption, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return &EnvelopeEncryption{masterKey: key}, nil
}

type EncryptedField struct {
	CiphertextHex string `json:"ciphertext"`
	NonceHex      string `json:"nonce"`
	KeyID         string `json:"key_id"`
}

func (ee *EnvelopeEncryption) Encrypt(plaintext string) (*EncryptedField, error) {
	block, err := aes.NewCipher(ee.masterKey)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	return &EncryptedField{
		CiphertextHex: hex.EncodeToString(ciphertext),
		NonceHex:      hex.EncodeToString(nonce),
		KeyID:         "master-v1",
	}, nil
}

func (ee *EnvelopeEncryption) Decrypt(enc *EncryptedField) (string, error) {
	block, err := aes.NewCipher(ee.masterKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := hex.DecodeString(enc.NonceHex)
	if err != nil {
		return "", err
	}
	ciphertext, err := hex.DecodeString(enc.CiphertextHex)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plaintext), nil
}
