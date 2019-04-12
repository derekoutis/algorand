package wolk

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	wolkcommon "github.com/mkchungs/algorand/common"
)

type Certificate struct {
	BlockNumber    uint64           `json:"blockNumber"`
	BlockHash      common.Hash      `json:"blockHash"`
	ParentHash     common.Hash      `json:"parentHash"`
	CompactedVotes []*CompactedVote `json:"compactedVotes"`
}

type Certs []*Certificate

func DecodeRLPCert(bytes []byte) (p *Proposal, err error) {
	var po Proposal
	err = rlp.DecodeBytes(bytes, &po)
	if err != nil {
		return p, err
	}
	return &po, nil
}

func (c *Certificate) Serialize() ([]byte, error) {
	return json.Marshal(c)
}

func (c *Certificate) Deserialize(data []byte) error {
	return json.Unmarshal(data, c)
}

func (c *Certificate) Verify(weight uint64, m []byte) error {
	//TODO: figure out the verify logic here
	return nil
}

func (c *Certificate) Hash() (h common.Hash) {
	enc, _ := rlp.EncodeToBytes(&c)
	return common.BytesToHash(wolkcommon.Computehash(enc))
}

func (c *Certificate) Hex() string {
	return fmt.Sprintf("%x", c.Bytes())
}

func (c *Certificate) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&c)
	return enc
}

func (c *Certificate) Size() uint64 {
	return uint64(len(c.Bytes()))
}

func (c *Certificate) Unpack() []*VoteMessage {
	votes := []*VoteMessage{}
	blocknum := c.BlockNumber
	blockhash := c.BlockHash
	parenthash := c.ParentHash
	for _, cv := range c.CompactedVotes {
		v := cv.Unpack(blocknum, blockhash, parenthash)
		votes = append(votes, v)
	}
	return votes
}

type SerializedCertificate struct {
	VoteCount      uint64                     `json:"VoteCount"`
	BlockNumber    uint64                     `json:"blockNumber"`
	BlockHash      common.Hash                `json:"blockHash"`
	ParentHash     common.Hash                `json:"parentHash"`
	CompactedVotes []*SerializedCompactedVote `json:"compactedVotes"`
	Certsize       uint64                     `json:"certsize"`
}

func (sc *SerializedCertificate) DeserializeCertificate() *Certificate {
	cert := new(Certificate)
	cert.BlockNumber = sc.BlockNumber
	cert.BlockHash = sc.BlockHash
	cert.ParentHash = sc.ParentHash

	for _, scv := range sc.CompactedVotes {
		cv := scv.DeserializeCompactedVote()
		cert.CompactedVotes = append(cert.CompactedVotes, cv)
	}
	return cert
}

func NewSerializedCertificate(c *Certificate) *SerializedCertificate {
	sc := &SerializedCertificate{
		VoteCount:      0,
		BlockNumber:    c.BlockNumber,
		BlockHash:      c.BlockHash,
		ParentHash:     c.ParentHash,
		CompactedVotes: make([]*SerializedCompactedVote, 0),
		Certsize:       c.Size(),
	}

	for _, cv := range c.CompactedVotes {
		scv := NewSerializeCompactedVote(cv)
		sc.CompactedVotes = append(sc.CompactedVotes, scv)
		sc.VoteCount = sc.VoteCount + cv.Sub
	}
	return sc
}

func (c *Certificate) String() string {
	s := NewSerializedCertificate(c)
	return s.String()
}

func (sc *SerializedCertificate) String() string {
	bytes, err := json.Marshal(sc)
	if err != nil {
		return "{}"
	} else {
		return string(bytes)
	}
}
