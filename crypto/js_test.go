package crypto

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	jose "gopkg.in/square/go-jose.v1"
)

/*
<html>
<head>
<script>
function toHexString(byteArray)
{
  return Array.prototype.map.call(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function toHexString(byteArray)
{
  return Array.prototype.map.call(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function genkey() {
  window.crypto.subtle.generateKey(
      {
          name: "ECDSA",
          namedCurve: "P-256",
      },
      true, //whether the key is extractable (i.e. can be used in exportKey)
      ["sign", "verify"] //can be any combination of "sign" and "verify"
  )
  .then(function(key){
      //returns a keypair object
      console.log(key);
    //  console.log(key.publicKey);
    //  console.log(key.privateKey);

    var enc = new TextEncoder(); // always utf-8
    m = enc.encode("A");

      window.crypto.subtle.exportKey(
          "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
        key.publicKey //can be a publicKey or privateKey, as long as extractable was true
      )
      .then(function(keydata){
        console.log('exportKey1:', keydata);
        console.log('exportKey2:', JSON.stringify(keydata));
      })
      .catch(function(err){
        console.error(err);
      });
      window.crypto.subtle.digest(
        {
            name: "SHA-256",
        },
         m //new  Uint8Array([65]) //The data you want to hash as an ArrayBuffer
       )
       .then(function(hash){
        console.log('SHA256:', toHexString(new Uint8Array(hash)));
        window.crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
            },
            key.privateKey, //from generateKey or importKey above
            m //ArrayBuffer of data you want to sign
        )
        .then(function(signature){
            //returns an ArrayBuffer containing the signature
            console.log('Sig:', toHexString(new Uint8Array(signature)));
        })
        .catch(function(err){
            console.error(err);
        });
      })
      .catch(function(err){
          console.error(err);
        });
  })
  .catch(function(err){
      console.error(err);
  });
}

</script>
</head>
<body>
  <h4>TestCrypto on Wolk Browser + Extension</h4>
  <input type=button onClick="genkey();" value="Generate ECDSA Key, ExportKey and Output signed SHA256('A') to log"/>
</body>
</html>*/

func TestJS(t *testing.T) {
	jwk := `{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"JoO-7wabEQy2Ey5ZwDnT0Nsr-B9MGec9jteFw9pilyY","y":"Ruz9VmyyfzI-qxdQ4aVm-Y9rGolkkU7WMdB8q9WIdkQ"}`
	hashbytes := common.FromHex("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd")
	sig := common.FromHex("ac5f2df16d9bd4846e5168af5818b279a18833cbab7151fa91fa4e1efb84f4987cb6aab20d03399d8b0bb3254f5c2eed148d1b5ec0691f89bbd819a280d4172e")

	var j jose.JsonWebKey
	err := j.UnmarshalJSON([]byte(jwk))
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	pk := j.Key.(*ecdsa.PublicKey)
	if ecdsa.Verify(pk, hashbytes, new(big.Int).SetBytes(sig[0:32]), new(big.Int).SetBytes(sig[32:64])) {
		fmt.Printf("VERIFIED\n")
	} else {
		fmt.Printf("NOT VERIFIED [%d]\n", len(sig))
	}
}
