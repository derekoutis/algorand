package wolk

import "time"

var (
	UserAmount     uint64 = 8
	TokenPerUser   uint64 = 125
	Malicious      uint64 = 0
	NetworkLatency        = 0
)

func getStepType(code uint64) interface{} {
	switch code {
	case 1000:
		return "PROPOSE"
	case 1001:
		return "REDUCTION_ONE"
	case 1002:
		return "REDUCTION_TWO"
	case 1003:
		return "FINAL"
	default:
		return code
	}
}

func getConsensusType(code int8) interface{} {
	switch code {
	case 0:
		return "FINAL_CONSENSUS"
	case 1:
		return "TENTATIVE_CONSENSUS"
	default:
		return code
	}
}

func TotalTokenAmount() uint64 { return UserAmount * TokenPerUser }

const (
	/*
		Algorand system parameters
		expectedBlockProposers        = 26    // τ_proposer
		expectedCommitteeMembers      = 10    // τ_step
		expectedFinalCommitteeMembers = 20    // τ_final
		thresholdOfBAStep             = 0.685 // T_step,  >= 2/3
		finalThreshold                = 0.74  // T_final, >= 2/3
		MAXSTEPS                      = 150

		timeout parameters (λ)
		lamdaPriority = 5 * time.Second  			// λ_priority 	time to gossip sortition proofs.
		lamdaBlock    = 1 * time.Minute  			// λ_Block 			timeout for receiving a block.
		lamdaStep     = 20 * time.Second 			// λ_Step 			timeout for BA* step.
		lamdaStepvar  = 5 * time.Second  			// λ_StepVAR		estimate of BA* completion time variance.
	*/

	//Algorand system parameters (τ,T)
	expectedBlockProposers        = 25
	expectedCommitteeMembers      = 100
	expectedFinalCommitteeMembers = 100
	MAXSTEPS                      = 150
	finalThreshold                = 0.4
	thresholdOfBAStep             = 0.4

	//timeout parameters (λ)
	lamdaPriority = 15 * time.Second // λ_priority 	time to gossip sortition proofs.
	lamdaBlock    = 2 * time.Minute  // λ_Block 		timeout for receiving a block.
	lamdaStep     = 15 * time.Second // λ_Step 			timeout for BA* step.
	lamdaStepvar  = 10 * time.Second // λ_StepVAR		estimate of BA* completion time variance.

	// interval
	R                   = 1000          // seed refresh interval (# of rounds)
	forkResolveInterval = 1 * time.Hour // fork resolve interval time

	// helper const var
	committee = "committee"
	proposer  = "proposer"

	// step
	PROPOSE       = 1000
	REDUCTION_ONE = 1001
	REDUCTION_TWO = 1002
	FINAL         = 1003

	FINAL_CONSENSUS     = 0
	TENTATIVE_CONSENSUS = 1

	// Malicious type
	Honest = iota
	EvilBlockProposal
	EvilVoteEmpty
	EvilVoteNothing
)
