# Algorand-Cloudstore
Go implementation of Algorand algorithm based on the paper [[gilad-algorand-eprint](https://people.csail.mit.edu/nickolai/papers/gilad-algorand-eprint.pdf)]

Algorand-Cloudstore is build on top of previous contribution/code-base at [[Tinychain-Algorand](https://github.com/tinychain/algorand)]


## Modifications / Improvements

* Improved Algorand psuedo-code comments and parameter settings
* Fixed `maxpriority` logic for block proposal
* Fixed `verifySort` to take external pubkey
* Modified `emptyBlock` and `emptyHash` logic for state transitioning, with matching `vrfseed` verification
* Modified `peer` and `handler` for actual {`TxMsg`,`NewBlockMsg`,`ProposalMsg`,`CertMsg`} network gossiping  

## TODO

* Implement `certificate` for block validation (Stub ready)
* Debug current Fork issue & VoteTimeOut resolution

