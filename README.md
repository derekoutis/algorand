# Algorand-Cloudstore
Go implementation of Algorand algorithm based on the paper [[gilad-algorand-eprint](https://people.csail.mit.edu/nickolai/papers/gilad-algorand-eprint.pdf)]

Algorand-Cloudstore is build on top of previous contribution/code-base at [[Tinychain-Algorand](https://github.com/tinychain/algorand)]


## Modifications / Improvements

* Fixed `maxpriority` logic for block proposal
* Fixed `verifySort` to take external pubkey
* New `emptyBlock` and `EmptyHash` logic for state transitioning
* New `peer` and `handler` for network gossiping
* New `vrfseed` implementation


## TODO

* Implement `certificate` for block validation
* Fork resolving
