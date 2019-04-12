package wolk

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"time"

	common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	wolkcommon "github.com/mkchungs/algorand/common"
	"github.com/mkchungs/algorand/crypto"
)

var (
	errCountVotesTimeout = errors.New("count votes timeout")
)

type PID int

type Algorand struct {
	maliciousType int // true: honest user; false: malicious user.
	id            int
	privkey       *crypto.PrivateKey
	pubkey        *crypto.PublicKey
	chain         *WolkStore
	peer          *Peer
	quitCh        chan struct{}
	hangForever   chan struct{}
	isPoA         bool
}

// calling this from WolkStore
func NewAlgorand(wstore *WolkStore, id int, maliciousType int, isDeterministic bool) *Algorand {
	rand.Seed(time.Now().UnixNano())
	var priv *crypto.PrivateKey
	var pub *crypto.PublicKey
	if isDeterministic {
		k_str := fmt.Sprintf("%x", wolkcommon.Computehash([]byte(fmt.Sprintf("%d", id))))
		priv, _ = crypto.HexToEd25519(k_str)
		pub = priv.PublicKey()
		addr := pub.Address()
		seed := priv.ToSeed()
		log.Info(fmt.Sprintf("[algorand:NewAlgorand] Node%d [%v] seed: [%v] deterministic: %v", id, addr.Hex(), seed, isDeterministic))
	} else {
		pub, priv, _ = crypto.NewKeyPair()
	}

	usePOA := isDeterministic
	//usePOA := false
	alg := &Algorand{
		maliciousType: maliciousType,
		id:            id,
		privkey:       priv,
		pubkey:        pub,
		chain:         wstore,
		isPoA:         usePOA,
	}

	//go alg.Start()
	return alg
}

func (alg *Algorand) Start() {
	alg.quitCh = make(chan struct{})
	alg.hangForever = make(chan struct{})
	go alg.run()
}

func (alg *Algorand) Stop() {
	close(alg.quitCh)
	close(alg.hangForever)
}

// round returns the latest round number.
func (alg *Algorand) round() uint64 {
	return alg.lastBlock().Round()
}

// use Block
func (alg *Algorand) lastBlock() *Block {
	return alg.chain.lastBlock()
}

// weight returns the weight of the given address.
func (alg *Algorand) weight(address common.Address) uint64 {
	return TokenPerUser
}

// tokenOwn returns the token amount (weight) owned by self node.
func (alg *Algorand) tokenOwn() uint64 {
	return alg.weight(alg.Address())
}

//TODO: make certificate using votes here + remove votes from memory afterward
func (alg *Algorand) makeCert(blockhash common.Hash) *Certificate {
	var cert *Certificate
	return cert
}

// seed returns the vrf-based seed of block r.
func (alg *Algorand) vrfSeed(round uint64) (seed, proof []byte, err error) {
	if round == 0 {
		return alg.chain.Genesis().Seed, nil, nil
	}

	lastBlock := alg.chain.getByRound(round - 1)
	// last block is not genesis, verify the seed r-1.
	if round != 1 {
		lastParentBlock := alg.chain.get(lastBlock.ParentHash, lastBlock.Round()-1)
		lastBlockempty := alg.emptyBlock(round-1, lastParentBlock.Hash(), lastParentBlock.Seed) //should be identical to lastBlock
		m := bytes.Join([][]byte{lastParentBlock.Seed, wolkcommon.UIntToByte(lastBlock.Round())}, nil)

		if len(lastBlock.Proof) != 0 {
			// vrf-based seed for non-empty lastblock
			pubkey := crypto.RecoverPubkey(lastBlock.Sig)
			err = pubkey.VerifyVRF(lastBlock.Proof, m)
			if err != nil {
				log.Error("[algorand:vrfSeed]", "round", round, "last block VerifyVRF err", err)
			}
			// author field
			log.Info("[algorand:vrfSeed]", "round", round, "last block singer", pubkey.Address().Hex())
			// notes: only check for sig, not state transition
		} else {
			// vrf-based seed for empty lastblock
			emptyseed := wolkcommon.Computehash(m)
			log.Info("[algorand:vrfSeed]", "round", round, "m", common.Bytes2Hex(m), "lastBlock Seed", common.Bytes2Hex(lastBlock.Seed), "emptyseed", common.Bytes2Hex(emptyseed), "lastParentBlock", lastParentBlock, "lastBlock", lastBlock, "expted lastBlockempty", lastBlockempty)
			if round%3 == 0 {
				//err = errors.New("Induced empty vrfseed invalid")
			}
			if bytes.Compare(lastBlock.Seed, emptyseed) != 0 {
				//log.Error("[algorand:vrfSeed] mismatch", "round", round, "m", common.Bytes2Hex(m), "lastBlock Seed", common.Bytes2Hex(lastBlock.Seed), "emptyseed", common.Bytes2Hex(emptyseed), "lastParentBlock", lastParentBlock)
				log.Error("[algorand:vrfSeed] mismatch", "round", round, "m", common.Bytes2Hex(m), "lastBlock Seed", common.Bytes2Hex(lastBlock.Seed), "emptyseed", common.Bytes2Hex(emptyseed), "lastParentBlock", lastParentBlock, "lastBlock", lastBlock, "expted lastBlockempty", lastBlockempty)
				err = errors.New("empty vrfseed invalid")
			}
			// } else if bytes.Compare(lastBlock.Seed, m) != 0 {
			// 	// hash-based seed
			// 	err = errors.New("hash seed invalid")
			//
			// }
		}
		if err != nil {
			// seed r-1 invalid, replace lastblock seed with emptyseed hash
			seedR := bytes.Join([][]byte{lastBlock.Seed, wolkcommon.UIntToByte(lastBlock.Round() + 1)}, nil)
			newseed := wolkcommon.Computehash(seedR)
			log.Info("[algorand:vrfSeed] newseed", "round", round, "seed||r", common.Bytes2Hex(seedR), "H(seed||r)", common.Bytes2Hex(newseed), "err", err)
			//log.Error("vrfseed", "err", err, "round", round)
			return newseed, nil, nil
		}
	}
	seed, proof, err = alg.privkey.Evaluate(bytes.Join([][]byte{lastBlock.Seed, wolkcommon.UIntToByte(lastBlock.Round() + 1)}, nil))
	return
}

// sortitionSeed returns the selection seed with a refresh interval R.
func (alg *Algorand) sortitionSeed(round uint64) []byte {
	realR := round - 1
	mod := round % R
	if realR < mod {
		realR = 0
	} else {
		realR -= mod
	}

	return alg.chain.getByRound(realR).Seed
}

func (alg *Algorand) Address() common.Address {
	return common.BytesToAddress(alg.pubkey.Bytes())
}

// run performs the all procedures of Algorand algorithm in infinite loop.

func (alg *Algorand) run() {
	time.Sleep(100 * time.Millisecond)

	go alg.forkLoop()

	// propose block
	for {
		select {
		case <-alg.quitCh:
			return
		default:
			alg.processMain()
		}
	}

}

// forkLoop periodically resolves fork
func (alg *Algorand) forkLoop() {
	forkInterval := time.NewTicker(forkResolveInterval)

	for {
		select {
		case <-alg.quitCh:
			return
		case <-forkInterval.C:
			alg.processForkResolve()
		}
	}
}

// processMain performs the main processing of algorand algorithm.
func (alg *Algorand) processMain() {
	currRound := alg.round() + 1
	log.Info(fmt.Sprintf("*** Starting Consensus at Block %v [Node%v] [algorand:processMain]", currRound, alg.id))

	// 1. block proposal
	block := alg.blockProposal(false)
	log.Info(fmt.Sprintf("*** BA Init at block %d, empty Block? %v [Node%v] [algorand:processMain]", block.Round(), block.Sig == nil, alg.id))

	// 2. init BA with block with the highest priority.
	consensusType, block := alg.BA(currRound, block)

	// 3. reach consensus on a FINAL or TENTATIVE new block.
	log.Info(fmt.Sprintf("*** Reach Consensus at Block %d %s [Node%v], empty Block? %v (Type: %v) [algorand:processMain]", currRound, block.Hash().Hex(), alg.id, block.Sig == nil, getConsensusType(consensusType)))

	// 4. append to the chain.
	alg.chain.add(block)
	alg.chain.recordBlock(block)

	// 5. TODO: make block certificate
	certMsg := alg.makeCert(block.Hash())
	alg.chain.WriteCert(certMsg)
	//alg.chain.protocolManager.cert__Ch <- CertPreEvent{Cert: certMsg}

	//6. clear cache vote cache after cert is generated and written to cloudstore
	//TODO
}

// processForkResolve performs a special algorand processing to resolve fork.
func (alg *Algorand) processForkResolve() {
	// force quit the hanging in BA if any.
	log.Info(fmt.Sprintf("*** entered processForkResolve!!! [Node%v] [algorand:processForkResolve]", alg.id))
	close(alg.hangForever)

	// propose fork
	longest := alg.blockProposal(true)
	// init BA with a highest priority fork
	_, fork := alg.BA(longest.Round(), longest)
	// commit fork
	alg.chain.resolveFork(fork)

	alg.hangForever = make(chan struct{})
}

// proposeBlock proposes a new block.
// use Block
func (alg *Algorand) proposeBlock() *Block {
	currRound := alg.round() + 1

	seed, proof, err := alg.vrfSeed(currRound)
	if err != nil {
		log.Info("[algorand:proposeBlock] vrfSeed error", "err", err)
		return alg.emptyBlock(currRound, alg.lastBlock().Hash(), alg.lastBlock().Seed)
	}

	var blk *Block

	parentHash := alg.lastBlock().Hash()

	log.Info("[algorand:proposeBlock] lastblock", "parentHash", parentHash.Hex(), "lastblock", alg.lastBlock())
	blk, err = alg.chain.CreateBlock(parentHash, alg.chain.wolktxpool.txpool, alg.chain.policy)
	if err != nil {
		log.Error("[algorand:proposeBlock] CreateBlock ERR", "ERR", err)
		return alg.emptyBlock(currRound, alg.lastBlock().Hash(), alg.lastBlock().Seed)
	}

	//log.Info("proposed blk", "blk", blk)

	// blk.blockNumber = currRound
	blk.Seed = seed
	// blk.parentHash = alg.lastBlock().Hash()
	blk.Author = alg.pubkey.Address()
	blk.Time = uint64(time.Now().Unix())
	blk.Proof = proof

	bhash := blk.Hash()
	sign, _ := alg.privkey.Sign(bhash.Bytes())
	blk.Sig = sign

	log.Info(fmt.Sprintf("*** Node %d propose a new block #%d %s (%v) [algorand:proposeBlock]", alg.id, blk.Round(), blk.Hash().Hex(), blk))
	return blk
}

// use Block
func (alg *Algorand) proposeFork() *Block {
	longest := alg.lastBlock()
	return alg.emptyBlock(alg.round()+1, longest.Hash(), longest.Seed)
}

// blockProposal performs the block proposal procedure.
// use Block
func (alg *Algorand) blockProposal(resolveFork bool) *Block {
	log.Trace("[algorand:blockProposal] a**", "node", alg.id)
	round := alg.round() + 1

	vrf, proof, subusers := alg.sortition(alg.sortitionSeed(round), role(proposer, round, PROPOSE), expectedBlockProposers, alg.tokenOwn())
	// have been selected.
	log.Trace("[algorand:blockProposal] b**", "node", alg.id)
	overwrite := false
	isRRLeader := alg.id == 7 //&& alg.round() != 1
	//isRRLeader := alg.id%3 == 1
	//isRRLeader := true
	if isRRLeader && alg.isPoA {
		overwrite = true
	}

	log.Trace("[algorand:blockProposal] c**", "node", alg.id, "isPOA", alg.isPoA, "overwrite?", overwrite)
	if subusers > 0 && !alg.isPoA {
		log.Info(fmt.Sprintf("** Node %d has %d sub-users in block proposal [algorand:blockProposal]", alg.id, subusers))
	} else if overwrite {
		log.Info(fmt.Sprintf("** Node %d is POA proposer [v,p,j,r] = %x, %x, %v, %v [algorand:blockProposal]", alg.id, vrf, proof, subusers, round))
	} else if subusers > 0 {
		log.Info(fmt.Sprintf("** Node %d has %d sub-users in block proposal but is not in POA [algorand:blockProposal]", alg.id, subusers))
	}

	if (subusers > 0 && !alg.isPoA) || overwrite {
		var (
			// use Block
			newBlk *Block
			forked bool
			//proposalType int
		)

		if !resolveFork {
			newBlk = alg.proposeBlock()
			forked = false
			//proposalType = BLOCK_PROPOSAL
		} else {
			newBlk = alg.proposeFork()
			forked = true
			//proposalType = FORK_PROPOSAL
		}

		proposal := &Proposal{
			BlockNumber: newBlk.Round(),
			BlockHash:   newBlk.Hash(),
			Prior:       maxPriority(vrf, subusers),
			VRF:         vrf,
			Proof:       proof,
			Pubkey:      alg.pubkey.Bytes(),
		}

		//log.Info("[Node%d] blockProposal", "node", alg.id, "proposal", proposal, "proposalHash", proposal.Hash().Hex())
		log.Info(fmt.Sprintf("[Node%d] blockProposal [algorand:blockProposal]", alg.id), "proposal hash", proposal.Hash().Hex(), "proposal", proposal)
		err := alg.chain.WriteBlock(newBlk)
		if err != nil {
			log.Info("[algorand:blockProposal] block proposal writeblock", "writeblock err", err)
		}

		alg.chain.protocolManager.setMaxProposal(round, proposal)
		alg.chain.protocolManager.addBlock(newBlk.Hash(), newBlk)

		if alg.maliciousType == EvilBlockProposal && !resolveFork {
			//go alg.chain.protocolManager.Gossip(BLOCK, blkMsg, 0)
			//go alg.chain.protocolManager.halfGossip(proposalType, proposalMsg, 0)

			// gossip another version of block to the remaining half peers.
			// newBlk = alg.proposeBlock()
			// proposal = &Proposal{
			// 	Round:  newBlk.Round(),
			// 	Hash:   newBlk.Hash(),
			// 	Prior:  maxPriority(vrf, subusers),
			// 	VRF:    vrf,
			// 	Proof:  proof,
			// 	Pubkey: alg.pubkey.Bytes(),
			// }
			// blkMsg, _ = newBlk.Serialize()
			// proposalMsg, _ = proposal.Serialize()
			// go alg.chain.protocolManager.halfGossip(BLOCK, blkMsg, 1)
			// go alg.chain.protocolManager.halfGossip(proposalType, proposalMsg, 1)
		} else {
			//gossip block, proposal
			go alg.chain.protocolManager.BroadcastBlock(newBlk)
			alg.chain.protocolManager.proposal_Ch <- ProposalPreEvent{Proposal: proposal, Forked: forked}
			//go alg.chain.protocolManager.BroadcastProposal(proposal.Hash(), &ProposalWithType{Proposal: proposal, Forked: forked})
			//TODO: add gossip back
		}
	}

	// wait for λstepvar + λpriority time to identify the highest priority.
	timeoutForPriority := time.NewTimer(lamdaStepvar + lamdaPriority)
	<-timeoutForPriority.C

	// timeout for block gossiping.
	timeoutForBlockFlying := time.NewTimer(lamdaBlock)
	ticker := time.NewTicker(2000 * time.Millisecond)
	for {
		select {
		case <-timeoutForBlockFlying.C:
			// empty block
			log.Warn(fmt.Sprintf("** Node %d get timeoutForBlockFlying [algorand:blockProposal] ", alg.id))
			newblk := alg.emptyBlock(round, alg.lastBlock().Hash(), alg.lastBlock().Seed)
			alg.chain.protocolManager.addBlock(newblk.Hash(), newblk)
			err := alg.chain.WriteBlock(newblk)
			if err != nil {
				log.Info("[algorand:blockProposal] block proposal writeblock", "writeblock err", err)
			}
			return newblk
			//return alg.emptyBlock(round, alg.lastBlock().Hash(), alg.lastBlock().Seed)
		case <-ticker.C:
			// get the block with the highest priority
			pp := alg.chain.protocolManager.getMaxProposal(round)

			if pp == nil {
				//log.Trace("[algorand:blockProposal] proposal is nil, continue", "node", alg.id)
				continue
			}
			blk := alg.chain.protocolManager.getBlock(pp.BlockHash)
			if blk != nil {
				return blk
			}
			log.Info("[algorand:blockProposal] ** getBlock err: block is nil", "node", alg.id, "proposal", pp.BlockHash.Hex())
			//log.Info("non-empty max proposal", "node", alg.id, "proposal", pp.Hash.Hex())
		}
	}
}

// Algorithm 1: sortition runs cryptographic selection procedure and returns vrf,proof and amount of selected sub-users.
func (alg *Algorand) sortition(seed, role []byte, expectedNum int, weight uint64) (vrf, proof []byte, selected int) {
	log.Trace("[algorand:sortition] b1**", "node", alg.id)
	vrf, proof, _ = alg.privkey.Evaluate(constructSeed(seed, role))
	log.Trace("[algorand:sortition] b2**", "node", alg.id)
	selected = subUsers(expectedNum, weight, vrf, alg.id)
	log.Trace("[algorand:sortition] subUsers", "node", alg.id, "sub-user", selected)
	return
}

// NOTE: weight is not part of the input
// Algorithm 2: verifySort verifies the vrf and returns the amount of selected sub-users.
func (alg *Algorand) verifySort(pk *crypto.PublicKey, vrf, proof, seed, role []byte, expectedNum int) int {
	if err := pk.VerifyVRF(proof, constructSeed(seed, role)); err != nil {
		log.Info(fmt.Sprintf("[algorand:verifySort] VerifyVRF ERR: pk[%x] proof[%x] seed[%x] role[%x] seed||role [%x] ", alg.pubkey.Bytes(), vrf, seed, role, constructSeed(seed, role)))
		return 0
	}
	log.Trace(fmt.Sprintf("[algorand:verifySort] VerifyVRF: pk[%x] proof[%x] seed[%x] role[%x] seed||role [%x] ", alg.pubkey.Bytes(), vrf, seed, role, constructSeed(seed, role)))
	return subUsers(expectedNum, alg.tokenOwn(), vrf, alg.id)
}

//  Algorithm 4: committeeVote votes for `value`.
func (alg *Algorand) committeeVote(round uint64, step uint64, expectedNum int, hash common.Hash) error {
	if alg.maliciousType == EvilVoteNothing {
		// vote nothing
		return nil
	}

	// check if user is in committee using Sortition(Alg 1) for j > 0
	vrf, proof, j := alg.sortition(alg.sortitionSeed(round), role(committee, round, step), expectedNum, alg.tokenOwn())

	//log.Trace("[algorand:committeeVote] committeeVote", "ID", alg.id, "sub-user", j)
	// only committee members originate a message
	if j > 0 {
		// Gossip vote message
		voteMsg := &VoteMessage{
			BlockNumber: round,
			Step:        step,
			Sub:         uint64(j),
			VRF:         vrf,
			Proof:       proof,
			ParentHash:  alg.chain.last.Hash(),
			BlockHash:   hash,
		}
		_, err := voteMsg.Sign(alg.privkey)
		if err != nil {
			log.Info("[algorand:committeeVote] sign err", "ID", alg.id, "sub-user", j, "err", err)
			return err
		}
		//log.Info("[algorand:committeeVote] signed ", "ID", alg.id, "sub-user", j, "votemsg", voteMsg)
		//gossip vote
		alg.chain.protocolManager.vote_Ch <- VotePreEvent{Vote: voteMsg}
		//go alg.chain.protocolManager.BroadcastVote(voteMsg.Hash(), voteMsg)
	}
	return nil
}

// Algorithm 3: BA runs BA* for the next round, with a proposed block.
// use Block
func (alg *Algorand) BA(round uint64, block *Block) (int8, *Block) {
	var (
		// use Block
		newBlk *Block
		hash   common.Hash
	)
	/*
		//Phase 1: reduction
		if alg.maliciousType == EvilVoteEmpty {
			hash = alg.emptyHash(round, block.ParentHash(), block.Seed)
			alg.reduction(round, hash)
		} else {
			//fmt.Sprintf("*** BA reduction Start [%id]", alg.id)
			log.Info(fmt.Sprintf("*** BA reduction Start at Block %v [Node%v]", round, alg.id), "blockhash", block.Hash().Hex())
			hash = alg.reduction(round, block.Hash())
			log.Info(fmt.Sprintf("*** BA reduction Finish at Block %v [Node%v]", round, alg.id), "blockhash", hash.Hex())
		}

	*/
	//Phase 1: reduction
	log.Info(fmt.Sprintf("*** BA reduction Start at Block %v [Node%v] [algorand:BA]", round, alg.id), "blockhash", block.Hash().Hex())
	hash = alg.reduction(round, block.Hash())
	emptyBlock := alg.emptyBlock(round, block.ParentHash, block.Seed)
	log.Info(fmt.Sprintf("*** BA reduction Finish at Block %v [Node%v] [algorand:BA]", round, alg.id), "blockhash", hash.Hex())

	hash = alg.binaryBA(round, hash)
	log.Info(fmt.Sprintf("*** binaryBA complete at Block %v [Node%v] [algorand:BA]", round, alg.id), "blockhash", hash.Hex())

	// Check if we reached "final" or "tentative" consensus
	r, _ := alg.countVotes(round, FINAL, finalThreshold, expectedFinalCommitteeMembers, lamdaStep)

	newBlk = alg.chain.protocolManager.getBlock(hash)
	if newBlk == nil {
		newBlk = emptyBlock
		alg.chain.protocolManager.getBlock(hash)
	}

	/*
		prevHash := alg.lastBlock().Hash()
		prevSeed := alg.lastBlock().Seed

		if hash == alg.emptyHash(round, prevHash, prevSeed) {
			// empty block
			log.Info(fmt.Sprintf("*** binaryBA complete at Block %v [Node%v] -- empty block [algorand:BA]", round, alg.id), "blockhash", hash.Hex(), "prevHash", prevHash.Hex())
			newBlk = alg.emptyBlock(round, prevHash, prevSeed)
		} else {
			log.Info(fmt.Sprintf("*** binaryBA complete at Block %v [Node%v] -- non-empty block [algorand:BA]", round, alg.id), "blockhash", hash.Hex(), "prevHash", prevHash.Hex(), "emptyHash", alg.emptyHash(round, prevHash, prevSeed).Hex())
			newBlk = alg.chain.protocolManager.getBlock(hash)

			log.Info(fmt.Sprintf("*** binaryBA complete at Block %v [Node%v] -- non-empty block [algorand:BA]", round, alg.id), "block", newBlk, "emptyblock", alg.emptyBlock(round, prevHash, prevSeed))
		}
	*/

	//TODO: type can not be send as part of the hash
	if hash == r {
		newBlk.consensusType = FINAL_CONSENSUS
		log.Info(fmt.Sprintf("*** binaryBA complete at Block %v [Node%v] - final consensus [algorand:BA]", round, alg.id), "block", newBlk)
		return FINAL_CONSENSUS, newBlk
	} else {
		newBlk.consensusType = TENTATIVE_CONSENSUS
		log.Info(fmt.Sprintf("*** binaryBA complete at Block %v [Node%v] - tentative consensus [algorand:BA]", round, alg.id), "block", newBlk)
		return TENTATIVE_CONSENSUS, newBlk
	}
}

// Algorithm 7: The two-step reduction.
func (alg *Algorand) reduction(round uint64, hash common.Hash) common.Hash {
	// step 1: gossip the block hash
	alg.committeeVote(round, REDUCTION_ONE, expectedCommitteeMembers, hash)

	// other users might still be waiting for block proposals,
	// so set timeout for λblock + λstep
	hash1, err := alg.countVotes(round, REDUCTION_ONE, thresholdOfBAStep, expectedCommitteeMembers, lamdaBlock+lamdaStep)

	// step 2: re-gossip the popular block hash
	empty := alg.emptyHash(round, alg.chain.last.Hash(), alg.chain.last.Seed)

	if err == errCountVotesTimeout {
		alg.committeeVote(round, REDUCTION_TWO, expectedCommitteeMembers, empty)
	} else {
		alg.committeeVote(round, REDUCTION_TWO, expectedCommitteeMembers, hash1)
	}

	hash2, err := alg.countVotes(round, REDUCTION_TWO, thresholdOfBAStep, expectedCommitteeMembers, lamdaStep)
	if err == errCountVotesTimeout {
		return empty
	}
	return hash2
}

// Algorithm 8: binaryBA executes until consensus is reached on either the given `hash` or `empty_hash`.
func (alg *Algorand) binaryBA(round uint64, hash common.Hash) common.Hash {
	var (
		step         = uint64(1)
		preVoteRound = uint64(10)
		r            = hash
		err          error
	)
	empty := alg.emptyHash(round, alg.chain.last.Hash(), alg.chain.last.Seed)
	defer func() {
		log.Info(fmt.Sprintf("*** binaryBA complete with %d steps at Block %d [Node%v] [algorand:binaryBA]", step, round, alg.id))
	}()
	for step < MAXSTEPS {
		alg.committeeVote(round, step, expectedCommitteeMembers, r)
		r, err = alg.countVotes(round, step, thresholdOfBAStep, expectedCommitteeMembers, lamdaStep)
		if err == errCountVotesTimeout {
			r = hash
		} else if !bytes.Equal(r.Bytes(), empty.Bytes()) {
			for s := step + 1; s <= step+preVoteRound; s++ {
				//step 2 and 3
				alg.committeeVote(round, s, expectedCommitteeMembers, r)
			}
			if step == uint64(1) {
				alg.committeeVote(round, FINAL, expectedFinalCommitteeMembers, r)
			}
			return r
		}
		step++

		alg.committeeVote(round, step, expectedCommitteeMembers, r)
		r, err = alg.countVotes(round, step, thresholdOfBAStep, expectedCommitteeMembers, lamdaStep)
		if err == errCountVotesTimeout {
			r = empty
		} else if bytes.Equal(r.Bytes(), empty.Bytes()) {
			for s := step + 1; s <= step+preVoteRound; s++ {
				alg.committeeVote(round, s, expectedCommitteeMembers, r)
			}
			return r
		}
		step++

		alg.committeeVote(round, step, expectedCommitteeMembers, r)
		r, err = alg.countVotes(round, step, thresholdOfBAStep, expectedCommitteeMembers, lamdaStep)
		if err == errCountVotesTimeout {
			if alg.commonCoin(round, step, expectedCommitteeMembers) == 0 {
				r = hash
			} else {
				r = empty
			}
		}
		step++
	}

	log.Info(fmt.Sprintf("reach the maxstep hang forever [algorand:binaryBA]"))
	// hang forever
	// No consensus after MAXSTEPS; assume network problems, and rely on 8.2 ro recover liveness
	<-alg.chain.hangForever
	return common.Hash{}
}

//TODO: remove votes from memory afterward
func makeCert(votes []*VoteMessage) *Certificate {
	sort.Sort(VotesOrderedbyHash(votes))

	cert := new(Certificate)
	if len(votes) > 0 {
		firstVote := votes[0]
		cert.BlockNumber = firstVote.BlockNumber
		cert.BlockHash = firstVote.BlockHash
		cert.ParentHash = firstVote.ParentHash
	}

	compactedVotes := []*CompactedVote{}
	for _, vote := range votes {
		compactedVotes = append(compactedVotes, vote.Compacted())
	}
	cert.CompactedVotes = compactedVotes
	return cert
}

// Algorithm 5: countVotes counts votes for round and step.
func (alg *Algorand) countVotes(round uint64, step uint64, threshold float64, expectedNum int, timeout time.Duration) (common.Hash, error) {
	expired := time.NewTimer(timeout)
	counts := make(map[common.Hash]int)
	totalVotes := make(map[common.Hash][]*VoteMessage)
	voters := make(map[string]struct{})
	it := alg.chain.protocolManager.voteIterator(round, step)
	var thresholdIsMet bool
	var proposedHash common.Hash

	var s string
	for {
		msg := it.next()
		if msg == nil {
			select {
			case <-expired.C:
				// timeout
				s = fmt.Sprintf("Receive votes %v (<%v) at step %v in Block %v [Node%v]", counts[proposedHash], uint64(float64(expectedNum)*threshold), getStepType(step), round, alg.id)
				log.Info(fmt.Sprintf("[algorand:countVotes] VotesTimeoutT at step %v in Block %v [Node%v] %s", getStepType(step), round, alg.id, s))
				//remove votes from mem
				//alg.chain.protocolManager.clearVotes(round, step)
				return common.Hash{}, errCountVotesTimeout

			default:
				if thresholdIsMet {
					cert := makeCert(totalVotes[proposedHash])
					//alg.chain.protocolManager.clearVotes(round, step)
					alg.chain.protocolManager.addCert(round, step, cert)
					log.Info(fmt.Sprintf("[algorand:countVotes] Receive critical votes %v (>=%v) at step %v in Block %v [Node%v]", counts[proposedHash], uint64(float64(expectedNum)*threshold), getStepType(step), round, alg.id))
					//log.Info(fmt.Sprintf("[algorand:countVotes] Tallied Votes at step %v in Block %v [Node%v]", getStepType(step), round, alg.id), "cert", cert)
					return proposedHash, nil
				}
			}
		} else {
			voteMsg := msg.(*VoteMessage)
			isSameHash := bytes.Equal(proposedHash.Bytes(), voteMsg.BlockHash.Bytes())

			if thresholdIsMet && !isSameHash {
				continue
			}

			votes, hash, _ := alg.processMsg(msg.(*VoteMessage), expectedNum)
			pubkey := voteMsg.RecoverPubkey()
			if _, exist := voters[string(pubkey.Bytes())]; exist || votes == 0 {
				continue
			}
			voters[string(pubkey.Bytes())] = struct{}{}
			counts[hash] += votes

			if _, exist := totalVotes[hash]; !exist {
				totalVotes[hash] = []*VoteMessage{voteMsg}
			} else {
				totalVotes[hash] = append(totalVotes[hash], voteMsg)
			}

			if !thresholdIsMet {
				if uint64(counts[hash]) >= uint64(float64(expectedNum)*threshold) {
					thresholdIsMet = true
					proposedHash = hash
				} else if !isSameHash {
					if counts[hash] > counts[proposedHash] {
						proposedHash = hash
					}
				}
			}
		}
	}
}

// Algorithm 6. processMsg validates incoming vote message.
func (alg *Algorand) processMsg(message *VoteMessage, expectedNum int) (votes int, hash common.Hash, vrf []byte) {
	if err := message.VerifySignature(); err != nil {
		return 0, common.Hash{}, nil
	}

	// discard messages that do not extend this chain
	prevHash := message.ParentHash
	if !bytes.Equal(prevHash.Bytes(), alg.chain.last.Hash().Bytes()) {
		return 0, common.Hash{}, nil
	}

	votes = alg.verifySort(message.RecoverPubkey(), message.VRF, message.Proof, alg.sortitionSeed(message.BlockNumber), role(committee, message.BlockNumber, message.Step), expectedNum)
	if uint64(votes) != message.Sub {
		log.Error(fmt.Sprintf("[algorand:processMsg] Malicious Vote (sub: %d | claimed: %d) [Node%v]", votes, message.Sub, alg.id), "vote", message)
	}
	hash = message.BlockHash
	vrf = message.VRF
	return
}

// Algorithm 9: commonCoin computes a coin common to all users.
// It is a procedure to help Algorand recover if an adversary sends faulty messages to the network and prevents the network from coming to consensus.
func (alg *Algorand) commonCoin(round uint64, step uint64, expectedNum int) int64 {
	minhash := new(big.Int).Exp(big.NewInt(2), big.NewInt(common.HashLength), big.NewInt(0))
	msgList := alg.chain.protocolManager.getIncomingMsgs(round, step)
	for _, m := range msgList {
		msg := m.(*VoteMessage)
		votes, _, vrf := alg.processMsg(msg, expectedNum)
		for j := 1; j < votes; j++ {
			h := new(big.Int).SetBytes(wolkcommon.Computehash(bytes.Join([][]byte{vrf, wolkcommon.UIntToByte(uint64(j))}, nil)))
			if h.Cmp(minhash) < 0 {
				minhash = h
			}
		}
	}
	return minhash.Mod(minhash, big.NewInt(2)).Int64()
}

// role returns the role bytes from current round and step
func role(iden string, round uint64, step uint64) []byte {
	return bytes.Join([][]byte{
		[]byte(iden),
		wolkcommon.UIntToByte(round),
		wolkcommon.UIntToByte(uint64(step)),
	}, nil)
}

/* original implementation:
// maxPriority returns the highest priority of block proposal.
func maxPriority(vrf []byte, users int) []byte {
	var maxPrior []byte
	for i := 1; i <= users; i++ {
		prior := wolkcommon.Computehash(bytes.Join([][]byte{vrf, common.UIntToByte(uint64(i))}, nil)).Bytes()
		if bytes.Compare(prior, maxPrior) > 0 {
			maxPrior = prior
		}
	}
	return maxPrior
}
*/

//Alternative version - reduce boundary by 1
func maxPriority(vrf []byte, users int) []byte {
	var maxPrior []byte
	for i := 0; i < users; i++ {
		prior := wolkcommon.Computehash(bytes.Join([][]byte{vrf, wolkcommon.UIntToByte(uint64(i))}, nil))
		if bytes.Compare(prior, maxPrior) > 0 {
			maxPrior = prior
		}
	}
	return maxPrior
}

// subUsers return the selected amount of sub-users determined from the mathematics protocol.
func subUsers(expectedNum int, weight uint64, vrf []byte, id int) int {
	//log.Info("subUsers b3**", "id", id, "expectedNum", expectedNum, "weight", weight)
	binomial := NewBinomial(int64(weight), int64(expectedNum), int64(TotalTokenAmount()))
	//log.Info("blockProposal b3-1**", "id", id)
	//binomial := NewApproxBinomial(int64(expectedNum), weight)
	//binomial := &distuv.Binomial{
	//	N: float64(weight),
	//	P: float64(expectedNum) / float64(TotalTokenAmount()),
	//}
	// hash / 2^hashlen ∉ [ ∑0,j B(k;w,p), ∑0,j+1 B(k;w,p))
	hashBig := new(big.Int).SetBytes(vrf)
	maxHash := new(big.Int).Exp(big.NewInt(2), big.NewInt(common.HashLength*8), nil)
	hash := new(big.Rat).SetFrac(hashBig, maxHash)
	var lower, upper *big.Rat
	j := 0
	for uint64(j) <= weight {
		//log.Trace("[algorand:subUsers] b3-2**", "id", id)
		if upper != nil {
			lower = upper
		} else {
			lower = binomial.CDF(int64(j))
		}
		upper = binomial.CDF(int64(j + 1))
		//log.Trace("[algorand:subUsers] b3-3**", "id", id)
		//log.Trace(fmt.Sprintf("[algorand:subUsers] hash %v, lower %v , upper %v", hash.Sign(), lower.Sign(), upper.Sign()))
		//log.Trace(fmt.Sprintf("[algorand:subUsers] j %d hash %x, lower %x , upper %x", j, hash, lower, upper))
		if hash.Cmp(lower) >= 0 && hash.Cmp(upper) < 0 {
			//log.Trace("[algorand:subUsers] b-3 break**", "id", id)
			break
		}
		j++
	}
	if uint64(j) > weight {
		j = 0
	}
	//log.Trace("[algorand:subUsers] b3-4**", "id", id, "sub-user", j)
	return j
}

// constructSeed construct a new bytes for vrf generation.
func constructSeed(seed, role []byte) []byte {
	return bytes.Join([][]byte{seed, role}, nil)
}

//emptyHash: return an empty bockHash when such block that doesn't involve state transition
func (alg *Algorand) emptyHash2(round uint64, prev common.Hash) common.Hash {
	b := alg.emptyBlock2(round, prev)
	return b.Hash()
}

func (alg *Algorand) emptyBlock2(round uint64, prevHash common.Hash) (unsigned *Block) {
	var prevblk *Block

	if round == 0 {
		prevblk = alg.chain.get(prevHash, round)
	} else {
		prevblk = alg.chain.get(prevHash, round-1)
	}

	if prevblk == nil {
		//Fall back to protocol manager
		log.Info(fmt.Sprintf("[algorand:emptyBlock2] [Node%d] Tentative Recovery state", alg.id), "prevHash", prevHash.Hex(), "blockNumber", round)
		prevblk = alg.chain.protocolManager.getBlock(prevHash)
	}

	if prevblk != nil {
		//seed := prevblk.Seed
		m := bytes.Join([][]byte{prevblk.Seed, wolkcommon.UIntToByte(prevblk.Round() + 1)}, nil)
		unsigned = &Block{
			ParentHash:    prevHash,
			BlockNumber:   round,
			Seed:          m,
			AccountRoot:   prevblk.AccountRoot,
			RegistryRoot:  prevblk.RegistryRoot,
			CheckRoot:     prevblk.CheckRoot,
			KeyRoot:       prevblk.KeyRoot,
			ProductsRoot:  prevblk.ProductsRoot,
			DeltaPos:      prevblk.DeltaPos,
			DeltaNeg:      prevblk.DeltaNeg,
			StorageBeta:   prevblk.StorageBeta,
			BandwidthBeta: prevblk.BandwidthBeta,
			PhaseVotes:    prevblk.PhaseVotes,
			Q:             prevblk.Q,
			Gamma:         prevblk.Gamma,
		}
	} else {
		//TODO: recursively get last available block
		log.Error(fmt.Sprintf("[algorand:emptyBlock2] [Node%d] Weird state - block not found", alg.id), "prevHash", prevHash.Hex(), "blockNumber", round)
		unsigned = &Block{
			ParentHash:  prevHash,
			BlockNumber: round,
		}
	}
	return unsigned
}

//emptyHash: return an empty bockHash when such block that doesn't involve state transition
func (alg *Algorand) emptyHash(round uint64, prevHash common.Hash, prevSeed []byte) common.Hash {
	//original implementation
	b := alg.emptyBlock(round, prevHash, prevSeed)
	return b.Hash()
}

//EmptyBlock: A block that doesn't involve state transition
func (alg *Algorand) emptyBlock(round uint64, prevHash common.Hash, prevSeed []byte) (unsigned *Block) {
	//TODO: load prevblock state
	seedR := bytes.Join([][]byte{prevSeed, wolkcommon.UIntToByte(round)}, nil)
	newseed := wolkcommon.Computehash(seedR)
	unsigned = &Block{
		ParentHash:  prevHash,
		BlockNumber: round,
		Seed:        newseed,
	}
	return unsigned
}
