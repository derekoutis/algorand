// Copyright 2018 Wolk Inc.  All rights reserved.
// This file is part of the Wolk Deep Blockchains library.
package common

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func Sign(data []byte, privateKey []byte) (signature []byte, err error) {
	ePrivateKey, err := crypto.HexToECDSA(common.Bytes2Hex(privateKey))
	if err != nil {
		return signature, fmt.Errorf("[deep:validate:Sign] crypto.HexToECDSA: %s", err)
	}
	encData := crypto.Keccak256(data)
	sig, err := crypto.Sign(encData, ePrivateKey)
	if err != nil {
		return signature, fmt.Errorf("[deep:validate:Sign] crypto.Sign: %s", err)
	}
	signature = make([]byte, 65) // not sure this is actually needed
	copy(signature, sig)
	return signature, nil
}

func ValidateSigner(data []byte, signature []byte, address common.Address) (bool, error) {
	signer, err := GetSigner(data, signature)
	if err != nil {
		return false, fmt.Errorf("[deep:validate:ValidateSigner] %s", err)
	}
	if signer != address {
		return false, nil
	}
	return true, nil
}

func GetSigner(data []byte, signature []byte) (address common.Address, err error) {
	encData := crypto.Keccak256(data)
	recoveredAddr, err := crypto.Ecrecover(encData, signature)
	if err != nil {
		return address, fmt.Errorf("[deep:validate:ValidateSigner] %s", err)
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(recoveredAddr[1:])[12:])
	return signer, nil
}

// get an operatorPrivateKey, Address pair for this operator
func GenerateAuthKeys() (privateKey []byte, address common.Address, err error) {
	eprivkey, err := crypto.GenerateKey()
	if err != nil {
		return privateKey, address, fmt.Errorf("[deep:validate:GenerateAuthKeys] %s", err)
	}
	privateKey = crypto.FromECDSA(eprivkey)
	pubKey := crypto.FromECDSAPub(&eprivkey.PublicKey)

	copy(address[:], crypto.Keccak256(pubKey[1:])[12:])

	return privateKey, address, nil
}
