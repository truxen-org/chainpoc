package txnutil

import (
	"encoding/pem"
	"io/ioutil"
	"log"
	"testing"
)

func TestPubKey(t *testing.T) {
	p, err := ioutil.ReadFile("../pcr/public.ecc.pem")
	if err != nil {
		log.Fatalln("Err", err)
	}
	if block, _ := pem.Decode(p); block != nil {
		if key, err := ParseECPublicKeyFromBlockBytes(block.Bytes); err == nil {
			log.Println("pubkey=", key)
		} else {
			log.Fatalln("Err", err)
		}
	}

}
