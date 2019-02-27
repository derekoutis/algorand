package wolk

import (
	"encoding/json"
	"fmt"

	wolkcommon "github.com/mkchungs/algorand/common"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/mkchungs/algorand/crypto"
)

const (
	// message type
	VOTE = iota
	BLOCK_PROPOSAL
	FORK_PROPOSAL
	BLOCK
)

type VoteMessage struct {
	BlockNumber uint64      `json:"blockNumber"`
	BlockHash   common.Hash `json:"blockHash"`
	ParentHash  common.Hash `json:"parentHash"`
	Step        uint64      `json:"step"`
	VRF         []byte      `json:"vrf"`
	Proof       []byte      `json:"proof"`
	Signature   []byte      `json:"signature"`
}

//compactedvote for certificate
type CompactedVote struct {
	Step      uint64 `json:"step"`
	VRF       []byte `json:"vrf"`       //potentially redundant
	Proof     []byte `json:"proof"`     //includes VRF
	Signature []byte `json:"signature"` // includes pubkey
}

type Votes []*VoteMessage

func DecodeRLPVote(bytes []byte) (v *VoteMessage, err error) {
	var vote VoteMessage
	err = rlp.DecodeBytes(bytes, &vote)
	if err != nil {
		return v, err
	}
	return &vote, nil
}

func (v *VoteMessage) Serialize() ([]byte, error) {
	return json.Marshal(v)
}

func (v *VoteMessage) Deserialize(data []byte) error {
	return json.Unmarshal(data, v)
}

func (v *VoteMessage) VerifySignature() error {
	pubkey := v.RecoverPubkey()
	msgHash := v.ShortHash()
	return pubkey.VerifySign(msgHash.Bytes(), v.Signature)
}

func (v *VoteMessage) Singer() common.Address {
	return crypto.RecoverPubkey(v.Signature).Address()
}

func (v *VoteMessage) Sign(priv *crypto.PrivateKey) ([]byte, error) {
	msgHash := v.ShortHash()
	sign, err := priv.Sign(msgHash.Bytes())
	if err != nil {
		return nil, err
	}
	v.Signature = sign
	return sign, nil
}

func (v *VoteMessage) ShortHash() common.Hash {
	unsignedmsg := &VoteMessage{
		BlockNumber: v.BlockNumber,
		BlockHash:   v.BlockHash,
		ParentHash:  v.ParentHash,
		Step:        v.Step,
		VRF:         v.VRF,
		Proof:       v.Proof,
		Signature:   make([]byte, 0),
	}
	enc, _ := rlp.EncodeToBytes(&unsignedmsg)
	return common.BytesToHash(wolkcommon.Keccak256(enc))
}

func (v *VoteMessage) Hash() common.Hash {
	enc, _ := rlp.EncodeToBytes(&v)
	return common.BytesToHash(wolkcommon.Keccak256(enc))
}

func (v *VoteMessage) Compacted() *CompactedVote {
	//var compact *CompactedVote
	compact := &CompactedVote{
		Step:      v.Step,
		VRF:       v.VRF,
		Proof:     v.Proof,
		Signature: v.Signature,
	}
	return compact
}

func (v *VoteMessage) String() string {
	if v != nil {
		return fmt.Sprintf("{\"blockNumber\":\"%d\", \"blockHash\":\"%x\", \"parentHash\":\"%x\", \"step\":\"%d\", \"vrf\":\"%x\", \"proof\":\"%x\", \"signature\":\"%x\", \"signer\":\"%x\"}",
			v.BlockNumber, v.BlockHash, v.ParentHash, v.Step, v.VRF, v.Proof, v.Signature, v.Singer())
	} else {
		return fmt.Sprint("{}")
	}
}

func (v *VoteMessage) RecoverPubkey() *crypto.PublicKey {
	return crypto.RecoverPubkey(v.Signature)
}
