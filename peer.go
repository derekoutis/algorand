// Copyright 2018 Wolk Inc.  All rights reserved.
// This file is part of the Wolk Deep Blockchains library.\
package wolk

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/log"
	set "gopkg.in/fatih/set.v0"
)

var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

const (
	maxKnownWolkTxs    = 32768 // Maximum app transactions hashes to keep in the known list (prevent DOS)
	maxKnownProposals  = 32768 // Maximum app Proposal hashes to keep in the known list (prevent DOS)
	maxKnownVotes      = 32768 // Maximum app Vote hashes to keep in the known list (prevent DOS)
	maxKnownWolkBlocks = 1024  // Maximum app block hashes to keep in the known list (prevent DOS)
	handshakeTimeout   = 5 * time.Second
)

// PeerInfo represents a short summary of the Ethereum sub-protocol metadata known
// about a connected peer.
type PeerInfo struct {
	Version int `json:"version"` // Ethereum protocol version negotiated
}

type peer struct {
	id string

	*p2p.Peer
	rw p2p.MsgReadWriter

	version  int         // Protocol version negotiated
	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time

	lock sync.RWMutex

	knownWolkBlocks set.Interface // Set of block hashes known to be known by this peer
	knownWolkTxs    set.Interface // Set of block hashes known to be known by this peer
	knownProposals  set.Interface // Set of block hashes known to be known by this peer
	knownVotes      set.Interface // Set of hashes known to be known by this peer
	knownCerts      set.Interface // Set of hashes known to be known by this peer
}

func newPeer(version int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	id := p.ID()
	return &peer{
		Peer:            p,
		rw:              rw,
		version:         version,
		id:              fmt.Sprintf("%x", id[:8]),
		knownWolkBlocks: set.New(),
		knownWolkTxs:    set.New(),
		knownProposals:  set.New(),
		knownVotes:      set.New(),
	}
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *peer) Info() *PeerInfo {
	return &PeerInfo{
		Version: p.version,
	}
}

// MarkWolkBlock marks a block as known for the peer, ensuring that the block will never be propagated to this particular peer.
func (p *peer) MarkWolkBlock(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known block hash
	for p.knownWolkBlocks.Size() >= maxKnownWolkBlocks {
		p.knownWolkBlocks.Pop()
	}
	p.knownWolkBlocks.Add(hash)
}

// MarkWolkTransaction marks a transaction as known for the peer, ensuring that it will never be propagated to this particular peer.
func (p *peer) MarkWolkTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownWolkTxs.Size() >= maxKnownWolkTxs {
		p.knownWolkTxs.Pop()
	}
	p.knownWolkTxs.Add(hash)
}

// MarkProposal marks a proposal as known for the peer, ensuring that it will never be propagated to this particular peer.
func (p *peer) MarkProposal(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownProposals.Size() >= maxKnownProposals {
		p.knownProposals.Pop()
	}
	p.knownProposals.Add(hash)
}

// MarkProposal marks a vote as known for the peer, ensuring that it will never be propagated to this particular peer.
func (p *peer) MarkVote(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownVotes.Size() >= maxKnownVotes {
		p.knownVotes.Pop()
	}
	p.knownVotes.Add(hash)
}

func (p *peer) SendProposals(proposals Proposals) error {
	for _, proposalWithType := range proposals {
		p.knownProposals.Add(proposalWithType.Proposal.Hash())
	}
	return p2p.Send(p.rw, ProposalMsg, proposals)
}

func (p *peer) SendVotes(votes Votes) error {
	for _, vote := range votes {
		p.knownVotes.Add(vote.Hash())
	}
	return p2p.Send(p.rw, VoteMsg, votes)
}

func (p *peer) SendCerts(certs Certs) error {
	for _, cert := range certs {
		p.knownCerts.Add(cert.Hash())
	}
	return p2p.Send(p.rw, CertMsg, certs)
}

func (p *peer) SendTransactions(txs WolkTransactions) error {
	for _, tx := range txs {
		p.knownWolkTxs.Add(tx.Hash())
	}
	return p2p.Send(p.rw, TxMsg, txs)
}

// SendNewBlock propagates an entire block to a remote peer.
func (p *peer) SendNewWolkBlock(block *Block) error {
	p.knownWolkBlocks.Add(block.Hash())
	sendErr := p2p.Send(p.rw, NewWolkBlockMsg, block)
	if sendErr != nil {
		log.Error("Error Sending Message", "error", sendErr)
		return sendErr
	}
	return nil
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *peer) Handshake(network uint64) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		errc <- p2p.Send(p.rw, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
		})
	}()
	go func() {
		errc <- p.readStatus(network, &status)
	}()
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				log.Debug("[peer:Handshake]", "err", err)
				return err
			}
		case <-timeout.C:
			log.Error("[peer:Handshake] DiscReadTimeout")
			return p2p.DiscReadTimeout
		}
	}

	return nil
}

func (p *peer) readStatus(network uint64, status *statusData) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		log.Debug("[peer:readStatus] ReadMsg", "err", err, "id", p.id, "ID", p.ID(), "localAddr", p.LocalAddr())
		return err
	}
	if msg.Code != StatusMsg {
		log.Debug("[peer:readStatus] ErrNoStatusMsg")
		return errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	if msg.Size > ProtocolMaxMsgSize {
		log.Debug("[peer:readStatus] ErrMsgTooLarge", "err", err)
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		log.Debug("[peer:readStatus] msg err", "err", err)
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if status.NetworkId != network {
		log.Debug("[peer:readStatus] ErrNetworkIdMismatch")
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if int(status.ProtocolVersion) != p.version {
		log.Debug("[peer:readStatus] ErrProtocolVersionMismatch")
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}
	return nil
}

// String implements fmt.Stringer.
func (p *peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("eth/%2d", p.version),
	)
}

// peerSet represents the collection of active peers currently participating in
// the Ethereum sub-protocol.
type peerSet struct {
	peers  map[string]*peer
	lock   sync.RWMutex
	closed bool
}

// newPeerSet creates a new peer set to track the active participants.
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peer),
	}
}

func (ps *peerSet) GetPeers() map[string]*peer {
	ps.lock.Lock()
	defer ps.lock.Unlock()
	return ps.peers
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known.
func (ps *peerSet) Register(p *peer) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	if ps.closed {
		return errClosed
	}
	if _, ok := ps.peers[p.id]; ok {
		return errAlreadyRegistered
	}
	ps.peers[p.id] = p
	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	if _, ok := ps.peers[id]; !ok {
		return errNotRegistered
	}
	delete(ps.peers, id)
	return nil
}

// Peer retrieves the registered peer with the given id.
func (ps *peerSet) Peer(id string) *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (ps *peerSet) PeersWithoutWolkBlock(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownWolkBlocks.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (ps *peerSet) PeersWithoutTx(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownWolkTxs.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutProposal retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (ps *peerSet) PeersWithoutProposal(hash common.Hash) ([]*peer, int) {
	ps.lock.RLock()
	defer ps.lock.RUnlock()
	covered := 0
	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownProposals.Has(hash) {
			list = append(list, p)
		} else {
			covered++
		}
	}
	return list, covered
}

// PeersWithoutVote retrieves a list of peers that do not have a given vote
// in their set of known hashes.
func (ps *peerSet) PeersWithoutVote(hash common.Hash) ([]*peer, int) {
	ps.lock.RLock()
	defer ps.lock.RUnlock()
	covered := 0
	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownVotes.Has(hash) {
			list = append(list, p)
		} else {
			covered++
		}
	}
	return list, covered
}

// CertWithoutVote retrieves a list of peers that do not have a given cert block
// in their set of known hashes.
func (ps *peerSet) PeersWithoutCert(hash common.Hash) ([]*peer, int) {
	ps.lock.RLock()
	defer ps.lock.RUnlock()
	covered := 0
	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownCerts.Has(hash) {
			list = append(list, p)
		} else {
			covered++
		}
	}
	return list, covered
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (ps *peerSet) Close() {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, p := range ps.peers {
		p.Disconnect(p2p.DiscQuitting)
	}
	ps.closed = true
}
