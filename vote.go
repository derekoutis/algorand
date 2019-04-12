package wolk

import (
	"bytes"
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
	Sub         uint64      `json:"subuser"`
	VRF         []byte      `json:"vrf"`
	Proof       []byte      `json:"proof"`
	Signature   []byte      `json:"signature"`
}

//compactedvote for certificate
type CompactedVote struct {
	Step      uint64 `json:"step"`
	Sub       uint64 `json:"subuser"`
	VRF       []byte `json:"vrf"`       //potentially redundant
	Proof     []byte `json:"proof"`     //includes VRF
	Signature []byte `json:"signature"` // includes pubkey
}

type Votes []*VoteMessage
type VotesOrderedbyHash Votes

func (votes VotesOrderedbyHash) Len() int      { return len(votes) }
func (votes VotesOrderedbyHash) Swap(i, j int) { votes[i], votes[j] = votes[j], votes[i] }
func (votes VotesOrderedbyHash) Less(i, j int) bool {
	if bytes.Compare(votes[i].Hash().Bytes(), votes[j].Hash().Bytes()) < 0 {
		return true
	} else {
		return false
	}
}

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
		Sub:         v.Sub,
		VRF:         v.VRF,
		Proof:       v.Proof,
		Signature:   make([]byte, 0),
	}
	enc, _ := rlp.EncodeToBytes(&unsignedmsg)
	return common.BytesToHash(wolkcommon.Computehash(enc))
}

func (v *VoteMessage) Hash() common.Hash {
	enc, _ := rlp.EncodeToBytes(&v)
	return common.BytesToHash(wolkcommon.Computehash(enc))
}

func (v *VoteMessage) Compacted() *CompactedVote {
	compact := &CompactedVote{
		Step:      v.Step,
		Sub:       v.Sub,
		VRF:       v.VRF,
		Proof:     v.Proof,
		Signature: v.Signature,
	}
	return compact
}

func (cv *CompactedVote) Unpack(bn uint64, blockhash, parenthash common.Hash) *VoteMessage {
	v := &VoteMessage{
		BlockNumber: bn,
		BlockHash:   blockhash,
		ParentHash:  parenthash,
		Step:        cv.Step,
		Sub:         cv.Sub,
		VRF:         cv.VRF,
		Proof:       cv.Proof,
		Signature:   cv.Signature,
	}
	return v
}

func (v *VoteMessage) RecoverPubkey() *crypto.PublicKey {
	return crypto.RecoverPubkey(v.Signature)
}

func (v *VoteMessage) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&v)
	return enc
}

func (cv *CompactedVote) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&cv)
	return enc
}

func (v *VoteMessage) Size() uint64 {
	return uint64(len(v.Bytes()))
}

func (cv *CompactedVote) Size() uint64 {
	return uint64(len(cv.Bytes()))
}

func (v *VoteMessage) String() string {
	sv := NewSerializedVote(v)
	return sv.String()
}

func (cv *CompactedVote) String() string {
	sv := NewSerializeCompactedVote(cv)
	return sv.String()
}

type SerializedVote struct {
	BlockNumber uint64      `json:"blockNumber"`
	BlockHash   common.Hash `json:"blockHash"`
	ParentHash  common.Hash `json:"parentHash"`
	Step        uint64      `json:"step"`
	Sub         uint64      `json:"subuser"`
	VRF         string      `json:"vrf"`
	Proof       string      `json:"proof"`
	Signature   string      `json:"signature"`
	Size        uint64      `json:"size"`
}

type SerializedCompactedVote struct {
	Step      uint64 `json:"step"`
	Sub       uint64 `json:"subuser"`
	VRF       string `json:"vrf"`
	Proof     string `json:"proof"`
	Signature string `json:"signature"`
	Size      uint64 `json:"size"`
}

func (sv *SerializedVote) DeserializeVote() *VoteMessage {
	v := new(VoteMessage)
	v.BlockNumber = sv.BlockNumber
	v.BlockHash = sv.BlockHash
	v.ParentHash = sv.ParentHash
	v.Step = sv.Step
	v.Sub = sv.Sub
	v.VRF = common.FromHex(sv.VRF)
	v.Proof = common.FromHex(sv.Proof)
	v.Signature = common.FromHex(sv.Signature)
	return v
}

func (scv *SerializedCompactedVote) DeserializeCompactedVote() *CompactedVote {
	cv := new(CompactedVote)
	cv.Step = scv.Step
	cv.Sub = scv.Sub
	cv.VRF = common.FromHex(scv.VRF)
	cv.Proof = common.FromHex(scv.Proof)
	cv.Signature = common.FromHex(scv.Signature)
	return cv
}

func NewSerializedVote(v *VoteMessage) *SerializedVote {
	return &SerializedVote{
		BlockNumber: v.BlockNumber,
		BlockHash:   v.BlockHash,
		ParentHash:  v.ParentHash,
		Step:        v.Step,
		Sub:         v.Sub,
		VRF:         fmt.Sprintf("%x", v.VRF),
		Proof:       fmt.Sprintf("%x", v.Proof),
		Signature:   fmt.Sprintf("%x", v.Signature),
		Size:        v.Size(),
	}
}

func NewSerializeCompactedVote(cv *CompactedVote) *SerializedCompactedVote {
	return &SerializedCompactedVote{
		Step:      cv.Step,
		Sub:       cv.Sub,
		VRF:       fmt.Sprintf("%x", cv.VRF),
		Proof:     fmt.Sprintf("%x", cv.Proof),
		Signature: fmt.Sprintf("%x", cv.Signature),
		Size:      cv.Size(),
	}
}

func (sv *SerializedVote) String() string {
	bytes, err := json.Marshal(sv)
	if err != nil {
		return "{}"
	} else {
		return string(bytes)
	}
}

func (scv *SerializedCompactedVote) String() string {
	bytes, err := json.Marshal(scv)
	if err != nil {
		return "{}"
	} else {
		return string(bytes)
	}
}
