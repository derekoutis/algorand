package wolk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	wolkcommon "github.com/mkchungs/algorand/common"
	"github.com/mkchungs/algorand/crypto"
)

var zeroHash common.Hash

type Proposal struct {
	BlockNumber uint64      `json:"blockNumber"`
	BlockHash   common.Hash `json:"blockHash"`
	Prior       []byte      `json:"prior"`
	VRF         []byte      `json:"vrf"` // vrf of user's sortition hash
	Proof       []byte      `json:"proof"`
	Pubkey      []byte      `json:"public_key"`
}

type Proposals []*ProposalWithType

type ProposalWithType struct {
	Proposal *Proposal
	Forked   bool
}

func DecodeRLPProposal(bytes []byte) (p *Proposal, err error) {
	var po Proposal
	err = rlp.DecodeBytes(bytes, &po)
	if err != nil {
		return p, err
	}
	return &po, nil
}

func (b *Proposal) Serialize() ([]byte, error) {
	return json.Marshal(b)
}

func (b *Proposal) Deserialize(data []byte) error {
	return json.Unmarshal(data, b)
}

func (b *Proposal) PublicKey() *crypto.PublicKey {
	return crypto.ByteToPublicKey(b.Pubkey)
}

func (b *Proposal) Address() common.Address {
	return b.PublicKey().Address()
}

func (b *Proposal) Verify(weight uint64, m []byte) error {
	// verify vrf
	pubkey := b.PublicKey()
	if err := pubkey.VerifyVRF(b.Proof, m); err != nil {
		return err
	}

	// verify priority
	subusers := subUsers(expectedBlockProposers, weight, b.VRF, 1)
	if bytes.Compare(maxPriority(b.VRF, subusers), b.Prior) != 0 {
		return errors.New("max priority mismatch")
	}
	return nil
}

func (p *Proposal) Hash() (h common.Hash) {
	enc, _ := rlp.EncodeToBytes(&p)
	return common.BytesToHash(wolkcommon.Keccak256(enc))
}

func (p *Proposal) String() string {
	if p != nil {
		return fmt.Sprintf("{\"blockNumber\":\"%d\", \"blockHash\":\"%x\", \"prior\":\"%x\", \"vrf\":\"%x\", \"proof\":\"%x\", \"public_key\":\"%x\"}",
			p.BlockNumber, p.BlockHash, p.Prior, p.VRF, p.Proof, p.Pubkey)
	} else {
		return fmt.Sprint("{}")
	}
}

func (p *Proposal) Hex() string {
	return fmt.Sprintf("%x", p.Bytes())
}

func (p *Proposal) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&p)
	return enc
}
