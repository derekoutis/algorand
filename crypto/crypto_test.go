package crypto

import (
	//"crypto"
	"fmt"
	"testing"

	wolkcommon "github.com/mkchungs/algorand/common"
)

func TestGenericSign(t *testing.T) {
	var priv *PrivateKey
	//var pub *PublicKey
	id := 27
	hash := wolkcommon.Keccak256([]byte(fmt.Sprintf("%d", id)))
	//fmt.Printf("SEED HEX: [%x]\nSEED BYTES [%+v]\n", hash, hash)
	k_str := fmt.Sprintf("%x", hash)
	priv, _ = HexToEd25519(k_str)
	//pub = priv.PublicKey()
	msgHash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	fmt.Printf("PublicKey Bytes: [%x] \n", priv.PublicKey().Bytes())
	//fmt.Printf("PrivateKey Bytes: [%x] \n", priv)
	manualSig, _ := priv.Sign(msgHash)

	fmt.Printf("MSGHASH [%x]\n", msgHash)
	fmt.Printf("SIG HEX [%x]\n", manualSig)
	fmt.Printf("SIG BYTES [%+v]\n", manualSig)
	//ExpectedSig := "70BED112B41C6A73AED3C31165F04539E4470453BD8A2A7B655D9BDE9FA15848E548B3B5343E857240E559DCBBCAE6A859952805FF3FB8572477ADBE770F6D0E"
}
