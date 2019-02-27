package wolk

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	wolkcommon "github.com/mkchungs/algorand/common"
)

//TODO: sigs, proof must be sorted & tallied
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
	return common.BytesToHash(wolkcommon.Keccak256(enc))
}

func (c *Certificate) Hex() string {
	return fmt.Sprintf("%x", c.Bytes())
}

func (c *Certificate) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&c)
	return enc
}
