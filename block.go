// Copyright 2018 Wolk Inc.  All rights reserved.
// This file is part of the Wolk Deep Blockchains library.
package wolk

import (

	// "encoding/json"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	wolkcommon "github.com/mkchungs/algorand/common"
	"github.com/mkchungs/algorand/crypto"
)

// NewMinedBlockEvent is posted when a block has been imported.
type NewMinedBlockEvent struct{ Block *Block }

type Block struct {
	ParentHash    common.Hash    `json:"parentHash"`
	BlockNumber   uint64         `json:"blockNumber"`
	Seed          []byte         `json:"seed"`         // vrf-based seed for next round
	AccountRoot   common.Hash    `json:"accountRoot"`  // SMT with keys being addresses, values being Account
	RegistryRoot  common.Hash    `json:"registryRoot"` // SMT with keys being node numbers, values being RegistryNode
	CheckRoot     common.Hash    `json:"checkRoot"`    // SMT with keys being CheckID, values being blockHashes containing the submitclaim
	KeyRoot       common.Hash    `json:"keyRoot"`
	ProductsRoot  common.Hash    `json:"productsRoot"`
	NameRoot      common.Hash    `json:"nameRoot"`
	Transactions  []*Transaction `json:"transactions"`
	DeltaPos      uint64         `json:"deltaPos"`      // valuation increase on Node
	DeltaNeg      uint64         `json:"deltaNeg"`      // valuation decrease on Node
	StorageBeta   uint64         `json:"storageBeta"`   //
	BandwidthBeta uint64         `json:"bandwidthBeta"` //
	PhaseVotes    uint64         `json:"phaseVotes"`    // once > 2/3 * 2^q, q is incremented and phaseVotes goes to 0
	Q             uint8          `json:"q"`
	Gamma         uint64         `json:"gamma"`        // used for taxation of node
	Author        common.Address `json:"author"`       // proposer address
	AuthorVRF     []byte         `json:"author_vrf"`   // sortition hash
	AuthorProof   []byte         `json:"author_proof"` // sortition hash proof
	Time          uint64         `json:"time"`         // block timestamp
	Proof         []byte         `json:"proof"`        // proof of vrf-based seed
	Sig           []byte         `json:"sig"`
	consensusType uint8          `json:"consensusType"`
}

func NewBlock() *Block {
	var b Block
	return &b
}

func (block Block) Hash() (h common.Hash) {
	data, _ := rlp.EncodeToBytes(&block)
	return common.BytesToHash(wolkcommon.Keccak256(data))
}

func (block *Block) BytesWithoutSig() []byte {
	enc, _ := rlp.EncodeToBytes(&block)
	if len(block.Sig) >= crypto.SignatureLength {
		return enc[0 : len(enc)-crypto.SignatureLength]
	} else {
		return enc
	}
}

func (b *Block) UnsignedHash() common.Hash {
	unsignedBytes := b.BytesWithoutSig()
	return common.BytesToHash(wolkcommon.Keccak256(unsignedBytes))
}

func (block *Block) ValidateBlock() (validated bool, err error) {
	pubkey := crypto.RecoverPubkey(block.Sig)
	err = pubkey.VerifySign(block.BytesWithoutSig(), block.Sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (b *Block) VerifySign() error {
	//TODO: check sig if it's not empty-hash
	pubkey := b.RecoverPubkey()
	msgHash := b.UnsignedHash()
	return pubkey.VerifySign(msgHash.Bytes(), b.Sig)
}

func (blk *Block) RecoverPubkey() *crypto.PublicKey {
	return crypto.RecoverPubkey(blk.Sig)
}

// TODO: check for Round usage in algorand package
func (blk *Block) Round() uint64 {
	return blk.BlockNumber
}

func (block Block) Root() (p common.Hash) {
	return block.UnsignedHash()
}

func (block Block) Number() (n uint64) {
	return block.BlockNumber
}

func FromChunk(in []byte) (b *Block) {
	var ob Block // []interface{}
	err := rlp.Decode(bytes.NewReader(in), &ob)
	if err != nil {
		return nil
	}
	return &ob
}

func (block Block) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(&block)
}

func (b *Block) GetSigner() (common.Address, error) {
	if len(b.Sig) == crypto.SignatureLength {
		return crypto.GetSigner(b.Sig)
	} else {
		return common.Address{}, nil
	}
}

func (b *Block) SignBlock(priv *crypto.PrivateKey) (err error) {
	b.Sig = make([]byte, crypto.SignatureLength)
	sig, err := priv.Sign(b.BytesWithoutSig())
	if err != nil {
		return err
	}
	b.Sig = make([]byte, crypto.SignatureLength)
	copy(b.Sig, sig)
	return nil
}

type SerializedBlock struct {
	ParentHash    common.Hash              `json:"parentHash"`
	BlockNumber   uint64                   `json:"blockNumber"`
	Seed          string                   `json:"seed"`
	AccountRoot   common.Hash              `json:"accountRoot"`  // SMT with keys being addresses, values being Account
	RegistryRoot  common.Hash              `json:"registryRoot"` // SMT with keys being node numbers, values being RegistryNode
	CheckRoot     common.Hash              `json:"checkRoot"`    // SMT with keys being CheckID, values being blockHashes containing the submitclaim
	KeyRoot       common.Hash              `json:"keyRoot"`
	ProductsRoot  common.Hash              `json:"productsRoot"`
	NameRoot      common.Hash              `json:"nameRoot"`
	Transactions  []*SerializedTransaction `json:"transactions"`
	DeltaPos      uint64                   `json:"deltaPos"`      // valuation increase on Node
	DeltaNeg      uint64                   `json:"deltaNeg"`      // valuation decrease on Node
	StorageBeta   uint64                   `json:"storageBeta"`   //
	BandwidthBeta uint64                   `json:"bandwidthBeta"` //
	PhaseVotes    uint64                   `json:"phaseVotes"`    // once > 2/3 * 2^q, q is incremented and phaseVotes goes to 0
	Q             uint8                    `json:"q"`
	Gamma         uint64                   `json:"gamma"`        // used for taxation of node
	Author        common.Address           `json:"author"`       // proposer address
	AuthorVRF     string                   `json:"author_vrf"`   // sortition hash
	AuthorProof   string                   `json:"author_proof"` // sortition hash proof
	Time          uint64                   `json:"time"`         // block timestamp
	Proof         string                   `json:"proof"`        // proof of vrf-based seed
	Sig           string                   `json:"sig"`
	Hash          common.Hash              `json:"hash"`
	Signer        common.Address           `json:"signer"`
	consensusType uint8                    `json:"consensusType"`
}

// func (block Block) Transactions() (txs []deep.Transaction) {
// 	return txs // block.transactions
// }

func (b *Block) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(b)
	return enc
}

func (b *Block) String() string {
	signer, err := b.GetSigner()
	if err != nil {
		signer = common.Address{}
	}
	s := &SerializedBlock{
		ParentHash:    b.ParentHash,
		BlockNumber:   b.BlockNumber,
		Seed:          fmt.Sprintf("%x", b.Seed),
		AccountRoot:   b.AccountRoot,
		RegistryRoot:  b.RegistryRoot,
		CheckRoot:     b.CheckRoot,
		KeyRoot:       b.KeyRoot,
		ProductsRoot:  b.ProductsRoot,
		NameRoot:      b.NameRoot,
		Transactions:  make([]*SerializedTransaction, 0),
		DeltaPos:      b.DeltaPos,
		DeltaNeg:      b.DeltaNeg,
		StorageBeta:   b.StorageBeta,
		BandwidthBeta: b.BandwidthBeta,
		PhaseVotes:    b.PhaseVotes,
		Q:             b.Q,
		Gamma:         b.Gamma,
		Author:        signer,
		AuthorVRF:     fmt.Sprintf("%x", b.AuthorVRF),
		AuthorProof:   fmt.Sprintf("%x", b.AuthorProof),
		Time:          b.Time,
		Proof:         fmt.Sprintf("%x", b.Proof),
		Sig:           fmt.Sprintf("%x", b.Sig),
		Hash:          b.Hash(),
		Signer:        signer,
		consensusType: b.consensusType,
	}

	for _, tx := range b.Transactions {
		stx := NewSerializedTransaction(tx)
		stx.BlockNumber = b.BlockNumber
		s.Transactions = append(s.Transactions, stx)
	}
	return s.String()
}

func (s *SerializedBlock) String() string {
	bytes, err := json.Marshal(s)
	if err != nil {
		return "{}"
	} else {
		return string(bytes)
	}
}
