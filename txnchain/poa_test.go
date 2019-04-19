package txnchain

import (
	"log"
	"testing"

	"github.com/truxen-org/chainpoc/txnutil"
)

func TestProposeRequest(t *testing.T) {
	pr := &ProposalRequest{
		Prop: &Proposal{
			Signer: txnutil.FromHex("295625abb1f2ca0803508fac5475b2021d83abb3"),
			Nonce:  NonceAuthVote,
		},
		Quoted:    txnutil.FromHex("ff54434780180022000b6393021b4f4321e5d3b9bf32a4bd23b006154c67d7b098aa965d325e5d45f7d900000000000053dfba8a7dd97ff6af374df301462ee85e71c6fc2a00000001000b03000007002083abfa3e0ed0df1130c487f17e164156308ec1faa432184a23a2a965f5898660"),
		Signature: txnutil.FromHex("30450221009fbcb1eb252faf079b4d5be1abf6ce501f78a38f142b399b3af3db9f0119a079022077e3abee4abf379108db9006d51504574227e7c8743b51953fdf897f77a5084e"),
		PubKey:    txnutil.FromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200047564a3b648dee3361b76036d1d093eb5a3356c261b04e95921c4f53df17f7bdbf3f02113a537689541c94c8884731904de88044e07b32441d2452dacb5a3ff28"),
	}
	v := pr.RlpValueEncode()
	npr := &ProposalRequest{}
	npr.RlpValueDecode(v)
	log.Println("restored: ", npr)
}
