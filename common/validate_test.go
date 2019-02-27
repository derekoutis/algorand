package common

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestValidate(t *testing.T) {

	pkey, address, err := GenerateAuthKeys()
	if err != nil {
		t.Fatal(err)
	}
	tprint("Generated: pkey(%v), address(%v)", common.Bytes2Hex(pkey), address.Hex())

	epkey, err := crypto.HexToECDSA(common.Bytes2Hex(pkey))
	if err != nil {
		t.Fatal(err)
	}
	data := crypto.Keccak256([]byte("randomdata"))
	expectedsig, err := crypto.Sign(data, epkey)
	if err != nil {
		t.Fatal(err)
	}
	actualsig, err := Sign([]byte("randomdata"), pkey)
	if err != nil {
		t.Fatal(err)
	}
	tprint("Signature: (%v)", common.Bytes2Hex(actualsig))
	if !bytes.Equal(actualsig, expectedsig) {
		tprint("actualsig(%v) vs expectedsig(%v)", common.Bytes2Hex(actualsig), common.Bytes2Hex(expectedsig))
		t.Fatalf("Sign() test fail: signatures do not match")
	}

	recoveredaddr, err := crypto.Ecrecover(data, expectedsig)
	if err != nil {
		t.Fatal(err)
	}
	var actualaddr common.Address
	copy(actualaddr[:], crypto.Keccak256(recoveredaddr[1:])[12:])
	if actualaddr != address {
		tprint("actualaddr(%v) vs expectedaddr(%v)", actualaddr.Hex(), address.Hex())
		t.Fatalf("GenerateAuthKeys() fail: recovered pub key is not the address")
	}

	ok, err := ValidateSigner([]byte("randomdata"), expectedsig, address)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("Verfy() fail: addresses did not match up")
	}
	tprint("Verify passed.")
}

func tprint(in string, args ...interface{}) {
	if in == "\n" {
		fmt.Println()
	} else {
		fmt.Printf("[test] "+in+"\n", args...)
	}
}
