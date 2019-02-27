// Copyright 2018 Wolk Inc.
// This file is part of the Wolk library.
package wolk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	wolkcommon "github.com/mkchungs/algorand/common"
	"github.com/mkchungs/algorand/crypto"
)

type Transaction struct {
	TransactionType uint8          `json:"transactionType"        gencodec:"required"` // 1=transfer, 2=register, 3=update, 4=check, 5=claim
	Recipient       common.Address `json:"recipient,omitempty"    gencodec:"required"` // 1=transfer, 6=setkey
	Amount          uint64         `json:"amount,omitempty"       gencodec:"required"` // 1=transfer, 2=register (>int+ext), 3=update (int)
	Node            uint64         `json:"node,omitempty"         gencodec:"required"` // 2=register, 3=update [node being registered or updated]
	GenericHash     common.Hash    `json:"hash,omitempty"         gencodec:"required"` // 4=check [hash], 5=claim [chunkID]
	StorageIP       []byte         `json:"storageip,omitempty"    gencodec:"required"` // 2=register, 3=update [IP]
	ConsensusIP     []byte         `json:"consensusip,omitempty"  gencodec:"required"` // 2=register, 3=update [IP]
	Region          uint8          `json:"region,omitempty"       gencodec:"required"` // 2=register, 3=update [IP]
	Collection      []byte         `json:"collection,omitempty"   gencodec:"required"` // 6=setkey, 7=updatecollections
	Key             []byte         `json:"key,omitempty"          gencodec:"required"` // 6=setkey, 7=updatecollections
	Data            []byte         `json:"data,omitempty" gencodec:"required`
	//Database        string         `json:"database,omitempty"gencodec:"required`
	Sig []byte `json:"sig,omitempty"` // all transactionTypes

	// not included in output, just for parse/unparse
	blockNumber uint64
	receipt     uint8
}

type Transactions []interface{}
type WolkTransactions []*Transaction

type TransactionMsg struct {
	TxType  uint64
	Payload []byte
}

const (
	TypeTransaction = 1

	TransactionTransfer       = 1
	TransactionRegisterNode   = 2
	TransactionUpdateNode     = 3
	TransactionBandwidthCheck = 4
	TransactionSetQuota       = 5
	TransactionSetKey         = 6
	TransactionDeleteKey      = 7
	TransactionSetName        = 8
	TransactionMutate         = 9
)

func DecodeRLPTransaction(txbytes []byte) (tx *Transaction, err error) {
	var txo Transaction
	err = rlp.DecodeBytes(txbytes, &txo)
	if err != nil {
		return tx, err
	}
	return &txo, nil
}

var emptyBytes = common.BytesToHash(make([]byte, 32))
var emptyRecipient = common.BytesToAddress(make([]byte, 20))

func NewTransactionTransfer(amount uint64, recipient common.Address) *Transaction {
	return &Transaction{
		TransactionType: TransactionTransfer,
		Recipient:       recipient,
		GenericHash:     emptyBytes,
		Amount:          amount,
	}
}

func NewTransactionSetName(name string, rsaPublicKeyBytes []byte) *Transaction {
	return &Transaction{
		TransactionType: TransactionSetName,
		Key:             []byte(name),
		Data:            rsaPublicKeyBytes,
	}
}

func NewTransactionRegisterNode(node uint64, storageip string, consensusip string, region uint8, value uint64) *Transaction {
	return &Transaction{
		TransactionType: TransactionRegisterNode,
		Node:            node,
		StorageIP:       []byte(storageip),
		ConsensusIP:     net.ParseIP(consensusip),
		Recipient:       emptyRecipient,
		Region:          region,
		GenericHash:     emptyBytes,
		Amount:          value,
	}
}

func NewTransactionUpdateNode(node uint64, storageip string, consensusip string, region uint8, valueInternal uint64) *Transaction {

	cip := net.ParseIP(consensusip)
	if cip == nil {
		return nil
	}
	return &Transaction{
		TransactionType: TransactionUpdateNode,
		Node:            node,
		Recipient:       emptyRecipient,
		StorageIP:       []byte(storageip),
		ConsensusIP:     cip.To4(),
		Region:          region,
		GenericHash:     emptyBytes,
		Amount:          valueInternal,
	}
}

func NewTransactionBandwidthCheck(checkChunkHash common.Hash) *Transaction {
	return &Transaction{
		TransactionType: TransactionBandwidthCheck,
		Recipient:       emptyRecipient,
		GenericHash:     checkChunkHash,
	}
}

func NewTransactionSetQuota(amount uint64) *Transaction {
	return &Transaction{
		TransactionType: TransactionSetQuota,
		Amount:          amount,
	}
}

// NoSQL
func NewTransactionSetKey(owner common.Address, collection string, key string, value common.Hash, sz uint64) *Transaction {
	return &Transaction{
		TransactionType: TransactionSetKey,
		Recipient:       owner,
		Collection:      []byte(collection),
		Key:             []byte(key),
		Amount:          sz,
		GenericHash:     value,
		Node:            uint64(time.Now().Unix()),
	}
}

//  name : sourabh.niyogi => address : 0x2341234123412341234 ==> stored in SMT with position of Keccak256(name) and value: TxHash
//  after something is written there, only the signer of the Tx can overwrite the position
func NewTransactionDeleteKey(owner common.Address, collection string, key string) *Transaction {
	return &Transaction{
		TransactionType: TransactionDeleteKey,
		Recipient:       owner,
		Collection:      []byte(collection),
		Key:             []byte(key),
	}
}

//SQL
//func NewTransactionMutate(owner common.Address, database string, query []byte) *Transaction {
func NewTransactionMutate(data []byte) *Transaction {
	// if len(data) > 0 {
	// 	data = common.CopyBytes(data)
	// }
	return &Transaction{
		TransactionType: TransactionMutate,
		//Recipient:       owner,
		//Database:        database,
		//Table: table,
		Data: data,

		//Amount: sz,
		//GenericHash: value,
		//Node: uint64(time.Now().Unix()),
	}
}

func (tx *Transaction) String() string {
	if tx != nil {
		stx := NewSerializedTransaction(tx)
		return stx.String()
	} else {
		return fmt.Sprint("{}")
	}

}

func (tx *Transaction) Size() common.StorageSize {
	return 1
}

// full hash
func (tx Transaction) Hash() common.Hash {
	return rlpHash([]interface{}{
		tx.TransactionType,
		tx.Recipient,
		tx.Amount,
		tx.Node,
		tx.GenericHash,
		tx.StorageIP,
		tx.ConsensusIP,
		tx.Region,
		tx.Collection,
		tx.Key,
		tx.Data,
		tx.Sig,
	})
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func (tx *Transaction) Hex() string {
	return fmt.Sprintf("%x", tx.Bytes())
}

func (tx *Transaction) Bytes() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&tx)
	return enc
}

func (tx *Transaction) BytesWithoutSig() (enc []byte) {
	enc, _ = rlp.EncodeToBytes(&tx)
	if len(tx.Sig) >= crypto.SignatureLength {
		return enc[0 : len(enc)-crypto.SignatureLength]
	} else {
		return enc
	}
}

// full RLP-encoded byte sequence
func BytesToTransaction(txbytes []byte) (ok bool, tx *Transaction) {
	tx, err := DecodeRLPTransaction(txbytes)
	if err != nil {
		fmt.Printf("Err %v", err)
		return false, tx
	}
	return true, tx
}

func getLastTransaction(history []*Transaction) (tx *Transaction) {
	if len(history) > 0 {
		return history[len(history)-1]
	} else {
		return nil
	}
}

// WARNING: state/ownership is not checked by signTX
func (tx *Transaction) SignTx(priv *crypto.PrivateKey) (err error) {
	var sig []byte
	if tx.TransactionType == TransactionSetKey {
		msg := MakeSetKeySignBytes(tx.Amount, tx.Recipient, string(tx.Collection), string(tx.Key)) // missing: Generic Hash
		sig, err = priv.Sign(msg)
		if err != nil {
			return fmt.Errorf("[transaction:SignTx] %s", err)
		}
	} else {
		tx.Sig = make([]byte, crypto.SignatureLength)
		sig, err = priv.Sign(tx.BytesWithoutSig())
		if err != nil {
			return fmt.Errorf("[transaction:SignTx] %s", err)
		}
	}
	tx.Sig = make([]byte, crypto.SignatureLength)
	copy(tx.Sig, sig)
	return nil
}

func (tx *Transaction) GetSigner() (address common.Address, err error) {
	if len(tx.Sig) == crypto.SignatureLength {
		return crypto.GetSigner(tx.Sig)
	} else {
		return common.Address{}, nil
	}
}

func MakeSetKeySignBytes(sz uint64, ownerAddr common.Address, collection string, key string) []byte {
	return append(wolkcommon.UInt64ToByte(sz), append(ownerAddr.Bytes(), append([]byte(collection), []byte(key)...)...)...)
}

func (tx *Transaction) ValidateTx() (bool, error) {

	if len(tx.Sig) != crypto.SignatureLength {
		log.Error("[transaction:ValidateTx] len not right", "tx.Sig", hex.EncodeToString(tx.Sig), "len", len(tx.Sig))
		return false, fmt.Errorf("Incorrect Sig length %d != %d", len(tx.Sig), crypto.SignatureLength)
	}
	if tx.TransactionType == TransactionSetName {
		if len(tx.Key) == 0 {
			return false, fmt.Errorf("Invalid name")
		}
	}
	if tx.TransactionType == TransactionSetKey {
		if len(tx.Collection) == 0 || len(tx.Collection) > 128 {
			return false, fmt.Errorf("Invalid collection name")
		}

		if len(tx.Key) == 0 || len(tx.Key) > 128 {
			return false, fmt.Errorf("Invalid key length")
		}
	}
	pubkey := crypto.RecoverPubkey(tx.Sig)
	// depending on the transaction type, we have user signing different bytes
	var msg []byte
	if tx.TransactionType == TransactionSetKey {
		msg = MakeSetKeySignBytes(tx.Amount, tx.Recipient, string(tx.Collection), string(tx.Key))
	} else {
		msg = tx.BytesWithoutSig()
	}
	log.Info("[transaction:ValidateTx] Node side calculated msg", "msg", fmt.Sprintf("%x", msg))
	err := pubkey.VerifySign(msg, tx.Sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

type SerializedTransaction struct {
	TransactionType uint8          `json:"transactionType"        gencodec:"required"` // 1=transfer, 2=register, 3=update, 4=check, 5=claim
	Recipient       common.Address `json:"recipient,omitempty"    gencodec:"required"` // 1=transfer, 6=setkey
	Amount          uint64         `json:"amount,omitempty"       gencodec:"required"` // 1=transfer, 2=register (>int+ext), 3=update (int)
	Node            uint64         `json:"node,omitempty"         gencodec:"required"` // 2=register, 3=update [node being registered or updated]
	GenericHash     common.Hash    `json:"hash,omitempty"         gencodec:"required"` // 4=check [hash], 5=claim [chunkID]
	StorageIP       []byte         `json:"ip,omitempty"           gencodec:"required"` // 2=register, 3=update [IP]
	ConsensusIP     []byte         `json:"consensusip,omitempty"  gencodec:"required"` // 2=register, 3=update [IP]
	Region          uint8          `json:"region,omitempty"       gencodec:"required"` // 2=register, 3=update [IP]
	Collection      string         `json:"collection,omitempty"   gencodec:"required"` // 6=setkey, 7=updatecollections
	Key             string         `json:"key,omitempty"          gencodec:"required"` // 6=setkey, 7=updatecollections
	Sig             string         `json:"sig,omitempty"`                              // all transactionTypes
	Data            string         `json:"data,omitempty" gencodec:"required"`
	TxHash          common.Hash    `json:"txhash"`
	BlockNumber     uint64         `json:"blockNumber"`
	Signer          common.Address `json:"signer"`
}

func (stx *SerializedTransaction) DeserializeTransaction() (n *Transaction) {
	n = new(Transaction)
	n.TransactionType = stx.TransactionType
	n.Recipient = stx.Recipient
	n.Amount = stx.Amount
	n.Node = stx.Node
	n.GenericHash = stx.GenericHash
	n.StorageIP = stx.StorageIP
	n.ConsensusIP = stx.ConsensusIP
	n.Region = stx.Region
	n.Collection = []byte(stx.Collection)
	n.Key = []byte(stx.Key)
	n.Sig = common.FromHex(stx.Sig) // hex
	n.Data = []byte(stx.Data)
	n.blockNumber = stx.BlockNumber
	return n
}

func NewSerializedTransaction(tx *Transaction) *SerializedTransaction {
	signer, err := tx.GetSigner()
	if err != nil {
		signer = common.Address{}
	}
	return &SerializedTransaction{
		TxHash:          tx.Hash(), // includes signature
		TransactionType: tx.TransactionType,
		Recipient:       tx.Recipient,
		Amount:          tx.Amount,
		Node:            tx.Node,
		GenericHash:     tx.GenericHash,
		StorageIP:       tx.StorageIP,
		ConsensusIP:     tx.ConsensusIP,
		Region:          tx.Region,
		Collection:      string(tx.Collection),
		Key:             string(tx.Key),
		Data:            string(tx.Data),
		Sig:             fmt.Sprintf("%x", tx.Sig),
		BlockNumber:     tx.blockNumber,
		Signer:          signer,
	}
}

func (stx *SerializedTransaction) String() string {
	bytes, err := json.Marshal(stx)
	if err != nil {
		return "{}"
	} else {
		return string(bytes)
	}
}
