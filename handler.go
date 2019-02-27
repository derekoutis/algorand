// Copyright 2018 Wolk Inc.  All rights reserved.
// This file is part of the Wolk Deep Blockchains library.\
package wolk

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	//	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"

	wolkcommon "github.com/mkchungs/algorand/common"
	"github.com/wolkdb/cloudstore/wolk/cloud"
	set "gopkg.in/fatih/set.v0"
)

// Constants to match up protocol versions and messages
const (
	wolk66 = 66
)

const maxKnownTxs = 10000

// Official short name of the protocol used during capability negotiation.
var ProtocolName = "wolk"

// Supported versions of the eth protocol (first is primary).
var ProtocolVersions = []uint{wolk66}

// Number of implemented message corresponding to different protocol versions.
var ProtocolLengths = []uint64{7}

const ProtocolMaxMsgSize = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message

// eth protocol message codes
const (
	// Wolk msg
	StatusMsg       = 0x01
	TxMsg           = 0x02
	NewWolkBlockMsg = 0x03
	ProposalMsg     = 0x04
	VoteMsg         = 0x05
	CertMsg         = 0x06
)

func getMsgType(code uint64) string {
	switch code {
	case 0x01:
		return "StatusMsg"
	case 0x02:
		return "TxMsg"
	case 0x03:
		return "NewWolkBlockMsg"
	case 0x04:
		return "ProposalMsg"
	case 0x05:
		return "VoteMsg"
	case 0x06:
		return "CertMsg"
	default:
		return "invalid Msg type"
	}
}

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
	ErrExtraStatusMsg
	ErrSuspendedPeer
)

// txChanSize is the size of channel listening to TxPreEvent.
// The number is referenced from the size of tx pool.
const (
	txChanSize       = 4096
	proposalChanSize = 409600
	voteChanSize     = 409600
)

func (e errCode) String() string {
	return errorToString[int(e)]
}

// TxPreEvent is posted when an transaction enters the transaction pool.
type TxPreEvent struct {
	Tx *Transaction
}

// ProposalPreEvent is posted when a blockproposal or forkproposal is broadcasted
type ProposalPreEvent struct {
	Proposal *Proposal
	Forked   bool
}

// VotePreEvent is posted when a Vote is broadcasted
type VotePreEvent struct {
	Vote *VoteMessage
}

// CertPreEvent is posted when a block Certificate is broadcasted
type CertPreEvent struct {
}

var errorToString = map[int]string{
	ErrMsgTooLarge:             "Message too long",
	ErrDecode:                  "Invalid message",
	ErrInvalidMsgCode:          "Invalid message code zzz",
	ErrProtocolVersionMismatch: "Protocol version mismatch",
	ErrNetworkIdMismatch:       "NetworkId mismatch",
	ErrGenesisBlockMismatch:    "Genesis block mismatch",
	ErrNoStatusMsg:             "No status message",
	ErrExtraStatusMsg:          "Extra status message",
	ErrSuspendedPeer:           "Suspended peer",
}

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	//appId             uint64
	networkId         uint64
	wolkChain         *WolkStore
	SubProtocols      []p2p.Protocol
	scope             event.SubscriptionScope
	newPeerCh         chan *peer // peer-related
	maxPeers          int
	peers             *peerSet
	noMorePeers       chan struct{}
	maxProposals      map[uint64]*Proposal // proposal-related
	proposal_Ch       chan ProposalPreEvent
	proposal_Sub      event.Subscription
	ProposalFeed      event.Feed
	pmu               sync.RWMutex // proposal list mutex
	incomingVotes     map[string]*List
	vote_Ch           chan VotePreEvent // vote-related
	vote_Sub          event.Subscription
	VoteFeed          event.Feed
	vmu               sync.RWMutex    // vote msg mutex
	txn_Ch            chan TxPreEvent // tx-related
	txn_Sub           event.Subscription
	TxFeed            event.Feed
	txpool            *TxPool
	txsyncCh          chan *txsync //not used?
	quitSync          chan struct{}
	cert_Ch           chan CertPreEvent // cert-related
	cert_Sub          event.Subscription
	CertFeed          event.Feed
	cmu               sync.RWMutex // cert mutex
	blocks            map[common.Hash]*Block
	minedBlockSub     *event.TypeMuxSubscription // cert-related
	eventMux          *event.TypeMux             // channels for fetcher, syncer, txsyncLoop
	bmu               sync.RWMutex               // block list mutex
	wg                sync.WaitGroup
	knownWolkBlocks   set.Interface // Set of block hashes known to be known by this peer
	knownWolkTxs      set.Interface // Set of tx hashes known to be known by this peer
	knownProposals    set.Interface // Set of proposal hashes known to be known by this peer
	knownCertificates set.Interface // Set of Certificates hashes known to be known by this peer
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(config *cloud.Config, mux *event.TypeMux, txpool *TxPool, chain *WolkStore) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkId:         config.NetworkId,
		eventMux:          mux,
		peers:             newPeerSet(),
		newPeerCh:         make(chan *peer),
		txsyncCh:          make(chan *txsync),
		quitSync:          make(chan struct{}),
		wolkChain:         chain,
		incomingVotes:     make(map[string]*List),
		blocks:            make(map[common.Hash]*Block),
		maxProposals:      make(map[uint64]*Proposal),
		txn_Ch:            make(chan TxPreEvent, txChanSize),
		proposal_Ch:       make(chan ProposalPreEvent, proposalChanSize),
		vote_Ch:           make(chan VotePreEvent, voteChanSize),
		txpool:            txpool,
		knownWolkBlocks:   set.New(),
		knownWolkTxs:      set.New(),
		knownProposals:    set.New(),
		knownCertificates: set.New(),
		//noMorePeers:  make(chan struct{}),
	}

	manager.txn_Sub = manager.SubscribeTxPreEvent(manager.txn_Ch)
	manager.proposal_Sub = manager.SubscribeProposalPreEvent(manager.proposal_Ch)
	manager.vote_Sub = manager.SubscribeVotePreEvent(manager.vote_Ch)
	manager.cert_Sub = manager.SubscribeCertPreEvent(manager.cert_Ch)
	manager.minedBlockSub = mux.Subscribe(NewMinedBlockEvent{})

	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				log.Info("[handler:NewProtocolManager] NewProtocolManager", "Node", manager.wolkChain.consensusIdx, "Run", p, "version", version)
				peer := manager.newPeer(int(version), p, rw)
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	return manager, nil
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	log.Debug("[handler:removePeer] Removing Ethereum peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	//pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		log.Error("[handler:removePeer] Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

// SubscribeTxPreEvent registers a subscription of TxPreEvent and
// starts sending event to the given channel.
func (pm *ProtocolManager) SubscribeTxPreEvent(ch chan<- TxPreEvent) event.Subscription {
	return pm.scope.Track(pm.TxFeed.Subscribe(ch))
}

// SubscribeTxPreEvent registers a subscription of ProposalPreEvent and
// starts sending event to the given channel.
func (pm *ProtocolManager) SubscribeProposalPreEvent(ch chan<- ProposalPreEvent) event.Subscription {
	return pm.scope.Track(pm.ProposalFeed.Subscribe(ch))
}

// SubscribeVotePreEvent registers a subscription of VotePreEvent and
// starts sending event to the given channel.
func (pm *ProtocolManager) SubscribeVotePreEvent(ch chan<- VotePreEvent) event.Subscription {
	return pm.scope.Track(pm.VoteFeed.Subscribe(ch))
}

// SubscribeVotePreEvent registers a subscription of CertPreEvent and
// starts sending event to the given channel.
func (pm *ProtocolManager) SubscribeCertPreEvent(ch chan<- CertPreEvent) event.Subscription {
	return pm.scope.Track(pm.CertFeed.Subscribe(ch))
}

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers
	go pm.txnBroadcastLoop()
	go pm.proposalBroadcastLoop()
	go pm.voteBroadcastLoop()
	go pm.certBroadcastLoop()
	go pm.generatedWolkBlockBroadcastLoop()

	// start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()
}

func (pm *ProtocolManager) Stop() {
	log.Info("[handler:Stop] Stopping Wolk protocol")

	pm.txn_Sub.Unsubscribe()       // quits txBroadcastLoop
	pm.proposal_Sub.Unsubscribe()  // quits proposalBroadcastLoop
	pm.vote_Sub.Unsubscribe()      // quits voteBroadcastLoop
	pm.cert_Sub.Unsubscribe()      // quits certBroadcastLoop
	pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	log.Info("[handler:Stop] Wolk protocol stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, rw)
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	// Ignore maxPeers if this is a trusted peer
	if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		return p2p.DiscTooManyPeers
	}
	log.Debug("[handler:handle] WOLK peer connecting", "name", p.Name(), "len(peers)", pm.peers.Len())

	// Execute the Ethereum handshake
	if err := p.Handshake(pm.networkId); err != nil {
		log.Debug("[handler:handle] WOLK handshake failed", "err", err)
		return err
	}
	log.Debug("[handler:handle] 2", "len(peers)", pm.peers.Len())

	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		log.Error("[handler:handle] WOLK peer registration failed", "err", err)
		return err
	}
	defer pm.removePeer(p.id)
	log.Debug("[handler:handle] 3", "len(peers)", pm.peers.Len())

	pm.syncTransactions(p)
	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			p.Log().Debug("[handler:handle] Ethereum message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	//TODO: Fail out if Regional ID Missing peer.RegId
	// Read the next message from the remote peer, and ensure it's fully consume
	msg, err := p.rw.ReadMsg()
	if err != nil {
		log.Error(fmt.Sprintf("[handler:handleMsg] Node%d handleMsg Error", pm.wolkChain.consensusIdx), "peer", p.ID(), "Error:", err)
		return err
	}
	//log.Trace(fmt.Sprintf("[handler:handleMsg] Node%d handleMsg received", pm.wolkChain.consensusIdx), "code", getMsgType(msg.Code), "peer", p.ID(), "msg", msg)
	/*WOLK review ProtocolMaxMsgSize */
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	// Handle the message depending on its contents
	switch {

	case msg.Code == VoteMsg:

		var votes []*VoteMessage
		if err := msg.Decode(&votes); err != nil {
			log.Info(fmt.Sprintf("[handler:handleMsg:VoteMsg] Node%d decode voteMsg error", pm.wolkChain.consensusIdx), "code", getMsgType(msg.Code), "peer", p.ID())
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		//log.Trace("[handler:handleMsg:VoteMsg] successfully decode votemsg", "code", getMsgType(msg.Code), "peer", p.ID())
		//log.Trace(fmt.Sprintf("[handler:handleMsg:VoteMsg] Node%d votemsg received", pm.wolkChain.consensusIdx), "code", getMsgType(msg.Code), "peer", p.ID(), "len", len(votes))

		for _, vote := range votes {
			key := constructVoteKey(vote.BlockNumber, vote.Step)
			pm.vmu.RLock()
			list, ok := pm.incomingVotes[key]
			pm.vmu.RUnlock()
			if !ok {
				list = newList()
			}
			list.add(vote)
			pm.vmu.Lock()
			pm.incomingVotes[key] = list
			pm.vmu.Unlock()

			p.MarkVote(vote.Hash())

			//TODO: broadcastvote
			pm.BroadcastVote(vote.Hash(), vote)
			//pm.vote_Ch <- VotePreEvent{Vote: vote}
		}

	case msg.Code == ProposalMsg: // typ == BLOCK_PROPOSAL || typ == FORK_PROPOSAL
		// Transactions can be processed, parse all of them and deliver to the pool

		//send single msg for now
		var proposalwithtypes []*ProposalWithType
		if err := msg.Decode(&proposalwithtypes); err != nil {
			log.Error(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d decode ProposalMsg error", pm.wolkChain.consensusIdx), "code", getMsgType(msg.Code))
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		//log.Trace(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d decode ProposalMsg received", pm.wolkChain.consensusIdx), "code", getMsgType(msg.Code), "peer", p.ID())

		shouldgossip := true
		proposalwithtype := proposalwithtypes[0]

		bp := proposalwithtype.Proposal
		pm.pmu.RLock()
		maxProposal := pm.maxProposals[bp.BlockNumber]
		pm.pmu.RUnlock()
		if maxProposal != nil {
			//maxProposal already set ... see if update is required
			if !proposalwithtype.Forked && bytes.Compare(bp.Prior, maxProposal.Prior) <= 0 {
				// "NOT forked" + bp.prior is less or equal to maxProposal.Prior
				if bytes.Compare(bp.Prior, maxProposal.Prior) == 0 || len(bp.Prior) == 0 {
					//log.Trace(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d Same Propposal", pm.wolkChain.consensusIdx), "Received BP Hash", bp.Hash().Hex(), "Max BP Hash", maxProposal.Hash().Hex())
					//return nil
				} else {
					//log.Trace(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d Drop Propposal", pm.wolkChain.consensusIdx), "received BP Prior", common.Bytes2Hex(bp.Prior), "maxProposal Prior", common.Bytes2Hex(maxProposal.Prior))
				}
				shouldgossip = false
			} else if proposalwithtype.Forked && bp.BlockNumber <= maxProposal.BlockNumber {
				log.Info("[handler:handleMsg:ProposalMsg] Propposal Forked is TRUE!!!", "Fork BP BlockNum", bp.BlockNumber, "maxProposal BlockNum", maxProposal.BlockNumber)
				return nil
			}
		}

		//TODO: set pointer to pm.algorand.weight
		if shouldgossip {
			if err := bp.Verify(pm.wolkChain.algorand.weight(bp.Address()), constructSeed(pm.wolkChain.algorand.sortitionSeed(bp.BlockNumber), role(proposer, bp.BlockNumber, PROPOSE))); err != nil {
				log.Error("[handler:handleMsg:ProposalMsg] block proposal verification failed, %s", err)
				return err
			}
		}

		p.MarkProposal(bp.Hash())
		// TODO: should put the maxproposal proposals into the proposal channel
		if shouldgossip {
			//log.Info("[handler:handleMsg:ProposalMsg] Gossip maxPropposal", "maxProposal", bp, "Forked", proposalwithtype.Forked)
			if maxProposal != nil {
				if len(bp.Prior) > 0 {
					log.Info(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d Updated Propposal ", pm.wolkChain.consensusIdx), "received BP Prior", common.Bytes2Hex(bp.Prior), "maxProposal Prior", common.Bytes2Hex(maxProposal.Prior))
				} else {
					log.Info(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d Updated Propposal ", pm.wolkChain.consensusIdx), "received BP Prior", common.Bytes2Hex(bp.Prior), "maxProposal Prior", common.Bytes2Hex(maxProposal.Prior))
				}
			} else {
				log.Info(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d Updated Propposal ", pm.wolkChain.consensusIdx), "received BP Prior", common.Bytes2Hex(bp.Prior))
			}

			pm.setMaxProposal(bp.BlockNumber, bp)
			pm.BroadcastProposal(bp.Hash(), proposalwithtype)
			//pm.proposal_Ch <- ProposalPreEvent{Proposal: bp, Forked: proposalwithtype.Forked}
		} else {

			pm.BroadcastProposal(bp.Hash(), proposalwithtype)
			//pm.proposal_Ch <- ProposalPreEvent{Proposal: maxProposal, Forked: false}
			//log.Info(fmt.Sprintf("[handler:handleMsg:ProposalMsg] Node%d Drop Proposal", pm.wolkChain.consensusIdx), "received BP Prior", common.Bytes2Hex(bp.Prior), "maxProposal Prior", common.Bytes2Hex(maxProposal.Prior), "Received BP Hash", bp.Hash().Hex(), "Max BP Hash", maxProposal.Hash().Hex())
		}

	case msg.Code == NewWolkBlockMsg:
		var wolkBlock *Block
		if err := msg.Decode(&wolkBlock); err != nil {
			log.Error(fmt.Sprintf("[handler:handleMsg:NewWolkBlockMsg] Node%d NewWolkBlockMsg error ", pm.wolkChain.consensusIdx), "Error", err)
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		//log.Info("[handler:handleMsg:NewWolkBlockMsg] received", "code", getMsgType(msg.Code), "peer", p.ID(), "blockhash", wolkBlock.Hash().Hex())

		if pm.wolkChain.ConsensusAlgorithm == "algorand" {
			pm.bmu.RLock()
			blk := pm.blocks[wolkBlock.Hash()]
			pm.bmu.RUnlock()

			if blk == nil {
				log.Info(fmt.Sprintf("[handler:handleMsg:NewWolkBlockMsg] Node%d Received New Block", pm.wolkChain.consensusIdx), "code", getMsgType(msg.Code), "peer", p.ID(), "blockhash", wolkBlock.Hash().Hex())
				pm.addBlock(wolkBlock.Hash(), wolkBlock)
			}
			p.MarkWolkBlock(wolkBlock.Hash())

			shouldgossip := true
			if shouldgossip {
				//log.Info("Gossip newblock", "blockhash", wolkBlock.Hash().Hex())
				pm.BroadcastBlock(wolkBlock)
				//pm.proposal_Ch <- ProposalPreEvent{Proposal: bp, Forked: proposalwithtype.Forked}
			}
		} else {
			/* POA NewWolkBlockMsg */

			// put the received block into the eventMux
			// pm.eventMux.Post(NewMinedBlockEvent{Block: wolkBlock})
			p.MarkWolkBlock(wolkBlock.Hash())
			// put the received block into the block channel
			if pm.wolkChain.consensusIdx != 0 {
				pm.wolkChain.ReceiveBlock(wolkBlock)
			}
		}

	case msg.Code == TxMsg:
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs WolkTransactions
		if err := msg.Decode(&txs); err != nil {
			log.Error(fmt.Sprintf("[handler:handleMsg:TxMsg] DECODE ERR [Node%d]", pm.wolkChain.consensusIdx), "err", err)
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			if pm.checkTransaction(tx.Hash()) {
				continue
			}
			pm.ValidateTransaction(tx.Hash())
			pm.markTransaction(tx.Hash())
			// don't send this back to the peer that just sent it to you!
			p.MarkWolkTransaction(tx.Hash())
			pm.txpool.addTransactionToPool(tx)
		}

		// put the received txs into the txn_Ch channel
		for _, tx := range txs {
			pm.txn_Ch <- TxPreEvent{Tx: tx}
		}

	case msg.Code == CertMsg:
	/*Stub: figure out the certificate logic here*/

	default:
		log.Debug("[handler:handleMsg] Code Not found", "Code:", msg.Code)
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

func (pm *ProtocolManager) GetPeers() []string {
	peers := pm.peers.GetPeers()
	//peersLen := pm.peers.Len()
	peersArr := make([]string, 0)
	for _, p := range peers {
		id := p.ID()
		enodeID := fmt.Sprintf("%x", id[:])
		remoteAddr := p.RemoteAddr() // net.Addr
		addr := fmt.Sprintf("%s", remoteAddr)
		enode := enodeID + "@" + addr
		peersArr = append(peersArr, enode)
	}
	log.Debug(fmt.Sprintf("[handler:GetPeers] peersArr: %s ", peersArr))
	return peersArr
}

// BroadcastTx will propagate a transaction to all peers which are not known to already have the given transaction.
func (pm *ProtocolManager) BroadcastTx(hash common.Hash, tx *Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.PeersWithoutTx(hash)
	for _, peer := range peers {
		err := peer.SendTransactions(WolkTransactions{tx})
		if err != nil {
			log.Error("[handler:BroadcastTx] Error Encountered Sending Wolk Transaction", "Error", err)
		}
	}
	log.Info("[handler:BroadcastTx] Broadcast wolk transaction", "hash", hash, "recipients", len(peers))
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *Block) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutWolkBlock(hash)
	// Send the wolk block to all of our peers
	for _, peer := range peers {
		log.Trace("[handler:BroadcastBlock] Sending to Peer", "idx", pm.wolkChain.consensusIdx, "peer", peer.ID())
		err := peer.SendNewWolkBlock(block)
		if err != nil {
			log.Error("[handler:BroadcastBlock] BroadcastBlock] Error Encountered Sending Wolk Block", "Error", err)
		}
	}
	if len(peers) > 0 {
		log.Info(fmt.Sprintf("[handler:BroadcastBlock] Node%d BroadcastBlock", pm.wolkChain.consensusIdx), "blockhash", block.Hash().Hex(), "bn", block.BlockNumber, "peer", pm.peers.Len(), "recipients", len(peers))
	}
}

// BroadcastProposal will propagate a proposal to all peers which are not known to already have the given proposal.
func (pm *ProtocolManager) BroadcastProposal(hash common.Hash, ptype *ProposalWithType) {
	//log.Info("BroadcastProposal", "hash", hash.Hex(), "Hash", ptype.Proposal.Hash().Hex(), "bn", ptype.Proposal.Round, "peers", pm.peers.Len())
	// Broadcast proposal to a batch of peers not knowing about it
	// TODO: add VRF logic
	peers, covered := pm.peers.PeersWithoutProposal(hash)
	for _, peer := range peers {
		err := peer.SendProposals(Proposals{ptype})
		if err != nil {
			log.Debug("[handler:BroadcastProposal] BroadcastProposal] Error Encountered Sending Proposal", "Error", err)
		}
	}
	//log.Info(fmt.Sprintf("[handler:BroadcastProposal] Node%d BroadcastProposal", pm.wolkChain.consensusIdx), "peers", len(peers))
	if len(peers) > 0 {
		log.Info(fmt.Sprintf("[handler:BroadcastProposal] Node%d BroadcastProposal", pm.wolkChain.consensusIdx), "hash", ptype.Proposal.Hash(), "bn", ptype.Proposal.BlockNumber, "peers", pm.peers.Len(), "recipients", len(peers), "covered", covered)
	}
}

// BroadcastProposal will propagate a Vote to all peers which are not known to already have the given proposal.
func (pm *ProtocolManager) BroadcastVote(hash common.Hash, vote *VoteMessage) {
	// Broadcast Vote to a batch of peers not knowing about it
	//TODO: add VRF logic
	peers, _ := pm.peers.PeersWithoutVote(hash)
	for _, peer := range peers {
		err := peer.SendVotes(Votes{vote})
		if err != nil {
			log.Debug("[handler:BroadcastVote] Error Encountered Sending Vote", "Error", err)
		}
	}
	if len(peers) > 0 {
		//log.Info(fmt.Sprintf("[handler:BroadcastVote] Node%d BroadcastVote", pm.wolkChain.consensusIdx), "hash", vote.Hash(), "bn", vote.Round, "step", getStepType(vote.Step), "recipients", len(peers), "covered", covered)
	}
}

// BroadcastCert will propagate a Cert to all peers which are not known to already have the given cert.
func (pm *ProtocolManager) BroadcastCert(hash common.Hash, cert *Certificate) {
	//TODO: add VRF logic + BLS logic here
	peers, _ := pm.peers.PeersWithoutCert(hash)
	for _, peer := range peers {
		err := peer.SendCerts(Certs{cert})
		if err != nil {
			log.Debug("[handler:BroadcastCert] Error Encountered Sending Vote", "Error", err)
		}
	}
	if len(peers) > 0 {
		//log.Info(fmt.Sprintf("[handler:BroadcastCert] Node%d BroadcastVote", pm.wolkChain.consensusIdx), "hash", vote.Hash(), "bn", vote.Round, "step", getStepType(vote.Step), "recipients", len(peers), "covered", covered)
	}
}

func (self *ProtocolManager) generatedWolkBlockBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case NewMinedBlockEvent:
			self.BroadcastBlock(ev.Block) // First propagate block to peers
		}
	}
	//log.Trace("[handler:BroadcastTx]", "hash", hash, "recipients", len(peers))
}

func (self *ProtocolManager) txnBroadcastLoop() {
	for {
		select {
		case event := <-self.txn_Ch:
			log.Info("[handler:wolk_txBroadcastLoop] Encountered wolk_txCh event and will attempt to broadcast", "txpool", self.txpool)
			self.BroadcastTx(event.Tx.Hash(), event.Tx)
		case <-self.txn_Sub.Err():
			log.Error("[handler:txnBroadcastLoop] Encountered txn_Ch err", "err", self.txn_Sub.Err())
			log.Error("[handler:wolk_txBroadcastLoop]", "txpool", self.txpool)
			return
		}
	}
}

func (self *ProtocolManager) proposalBroadcastLoop() {
	log.Trace("[handler:proposalBroadcastLoop]!!!!!")
	for {
		select {
		case event := <-self.proposal_Ch:
			log.Info("[handler:proposalBroadcastLoop] Encountered proposal_Ch event and will attempt to broadcast")
			//self.BroadcastProposal(event.Proposal.Hash(), event.Proposal)
			self.BroadcastProposal(event.Proposal.Hash(), &ProposalWithType{Proposal: event.Proposal, Forked: event.Forked})
		case <-self.proposal_Sub.Err():
			log.Error("[handler:proposalBroadcastLoop] Encountered proposal_Ch ERROR")
			return
		}
	}
}

func (self *ProtocolManager) voteBroadcastLoop() {
	log.Trace("[handler:voteBroadcastLoop]!!!!!")
	for {
		select {
		case event := <-self.vote_Ch:
			log.Trace("[handler:voteBroadcastLoop] Encountered vote_Ch event and will attempt to broadcast")
			self.BroadcastVote(event.Vote.Hash(), event.Vote)
		case <-self.vote_Sub.Err():
			log.Error("[handler:voteBroadcastLoop] Encountered vote_Ch ERROR")
			return
		}
	}
}

func (self *ProtocolManager) certBroadcastLoop() {
	log.Trace("[handler:certBroadcastLoop]!!!!!")
	for {
		select {
		case _ = <-self.cert_Ch:
			log.Trace("[handler:certBroadcastLoop] Encountered cert_Ch event and will attempt to broadcast")
			//self.BroadcastCert(event.cert_Ch.Hash(), event.Cert)
		case <-self.cert_Sub.Err():
			log.Error("[handler:certBroadcastLoop] Encountered cert_Ch ERROR")
			return
		}
	}
}

// NodeInfo represents a short summary of the Ethereum sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network uint64 `json:"network"` // Ethereum network ID
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (self *ProtocolManager) NodeInfo() *NodeInfo {
	return &NodeInfo{
		Network: self.networkId,
	}
}

func (self *ProtocolManager) checkTransaction(hash common.Hash) bool {
	return self.knownWolkTxs.Has(hash)
}

func (self *ProtocolManager) markTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for self.knownWolkTxs.Size() >= maxKnownWolkTxs {
		self.knownWolkTxs.Pop()
	}
	self.knownWolkTxs.Add(hash)
}

func (self *ProtocolManager) ValidateTransaction(hash common.Hash) bool {
	// TODO
	return true
}

func (self *ProtocolManager) ValidateProposal(hash common.Hash) bool {
	return true
}

func (self *ProtocolManager) CheckProposal(hash common.Hash) bool {
	return self.knownProposals.Has(hash)
}

func (p *ProtocolManager) setMaxProposal(round uint64, proposal *Proposal) {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	log.Info(fmt.Sprintf("[handler:setMaxProposal] Node%d set maxProposal #%d %s", p.wolkChain.consensusIdx, proposal.BlockNumber, proposal.BlockHash.Hex()), "Prior", common.Bytes2Hex(proposal.Prior))
	p.maxProposals[round] = proposal
}

func (p *ProtocolManager) getMaxProposal(round uint64) *Proposal {
	p.pmu.RLock()
	defer p.pmu.RUnlock()
	return p.maxProposals[round]
}

func (p *ProtocolManager) getIncomingMsgs(round uint64, step uint64) []interface{} {
	p.vmu.RLock()
	defer p.vmu.RUnlock()
	l := p.incomingVotes[constructVoteKey(round, step)]
	if l == nil {
		return nil
	}
	return l.list
}

func (p *ProtocolManager) getBlock(hash common.Hash) *Block {
	p.bmu.RLock()
	defer p.bmu.RUnlock()
	return p.blocks[hash]
}

func (p *ProtocolManager) addBlock(hash common.Hash, blk *Block) {
	p.bmu.Lock()
	defer p.bmu.Unlock()
	p.blocks[hash] = blk
}

// iterator returns the iterator of incoming messages queue.
func (p *ProtocolManager) voteIterator(round uint64, step uint64) *Iterator {
	key := constructVoteKey(round, step)
	p.vmu.RLock()
	list, ok := p.incomingVotes[key]
	p.vmu.RUnlock()
	if !ok {
		list = newList()
		p.vmu.Lock()
		p.incomingVotes[key] = list
		p.vmu.Unlock()
	}
	return &Iterator{
		list: list,
	}
}

func (p *ProtocolManager) clearProposal(round uint64) {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	delete(p.maxProposals, round)
}

func constructVoteKey(round uint64, step uint64) string {
	return string(bytes.Join([][]byte{
		wolkcommon.UIntToByte(round),
		wolkcommon.UIntToByte(uint64(step)),
	}, nil))
}

type List struct {
	mu   sync.RWMutex
	list []interface{}
}

func newList() *List {
	return &List{}
}

func (l *List) add(el interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, el)
}

func (l *List) get(index int) interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= len(l.list) {
		return nil
	}
	return l.list[index]
}

type Iterator struct {
	list  *List
	index int
}

func (it *Iterator) next() interface{} {
	el := it.list.get(it.index)
	if el == nil {
		return nil
	}
	it.index++
	return el
}

func (pm *ProtocolManager) NumPeers() int {
	return pm.peers.Len()
}
