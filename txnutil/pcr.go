package txnutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path"
	"strings"

	"crypto/elliptic"
	"crypto/rand"

	"github.com/truxen-org/chainpoc/crypto/math"
)

var (
	ErrPCRQuoteInfo      = errors.New("PCR quote not match")
	ErrNotECPublicKey    = errors.New("Key is not a valid ECDSA public key")
	ErrNotECPrivateKey   = errors.New("Key is not a valid ECDSA private key")
	ErrMustBePEMEncoded  = errors.New("Not pem encoded")
	ErrECDSAVerification = errors.New("DSA Verification failed")
	ErrSignatureSize     = errors.New("Wrong Signature Size")
)

var pcrPath string

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func InitPCR() {
	/* # Generate an ECC key
	openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem
	openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

	# Load the private key for signing
	tpm2_loadexternal -Q -G ecc -r private.ecc.pem -o key.ctx
	*/
	pcrPath = path.Join(Config.BaseDir, "pcr")
	if pcrthere, _ := exists(pcrPath); !pcrthere {
		log.Fatalf("no pcr folder in %s!", Config.BaseDir)
	}
	// tmpPath = path.Join(Config.BaseDir, ".tmp")
	// if tmpthere, _ := exists(tmpPath); !tmpthere {
	// 	os.Mkdir(tmpPath, os.ModePerm)
	// }
	// if _, err := os.Stat("./pcr/ca.cert.pem"); os.IsNotExist(err) {
	// 	panic("no ca.cert.pem!")
	//should be done manually since CA involved
	// log.Println("key.ctx does not exit; create new ...")
	// args1 := strings.Split("ecparam -name prime256v1 -genkey -noout -out private.ecc.pem", " ")
	// cmdWrapper("openssl", args1...)

	// args2 := strings.Split("ec -in private.ecc.pem -out public.ecc.pem -pubout", " ")
	// cmdWrapper("openssl", args2...)
	// GenerateKeyPairP256() not work well here.
	// }
	// args3 := strings.Split("-Q -G ecc -r private.ecc.pem -o key.ctx", " ")
	// _, err := cmdWrapper("tpm2_loadexternal", args3...)
	// if err != nil {
	// 	log.Fatalf("tpm2_loadexternal error: %v \n", err)
	// } else {
	// 	log.Println("load pcr done")
	// }
}

func cmdWrapper(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	// cmd.Dir = tmpPath
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return nil, err
	}
	// log.Println(string(opBytes))
	return opBytes, nil
}
func flushPCR() {
	_, err := cmdWrapper("tpm2_flushcontext", "-t")
	if err != nil {
		log.Println("Error tpm2_flushcontext", err)
		// } else {
		// 	Log.Debugln("tpm flush done.")
	}
}

//tpm2_quote -C key.ctx -G sha256 -L sha256:16,17,18 -f plain -s pcr.out.signed -m pcr.in.raw -q 12bbaa
func PCRSign(hashToSign string) ([]byte, []byte, error) {
	// defer flushPCR()
	args := strings.Split("-C 0x81010001 -G sha256 -L sha256:0,1,2,3,4,5,6,7,10,17,18 -f plain", " ")
	if hashToSign != "" {
		args = append(args, "-q")
		args = append(args, hashToSign)
	}
	// args = []string{"-h"}
	result, err := cmdWrapper("tpm2_quote", args...)
	if err != nil {
		// log.Fatal(err)
		return nil, nil, err
	}
	if result == nil || len(result) == 0 {
		// log.Fatal("signed nothing out.")
		return nil, nil, errors.New("PCR Error: signed nothing out.")
	}
	resultStr := string(result)
	// log.Println("\n", resultStr)
	end := strings.Index(resultStr, "signature:")
	quotedStr := resultStr[7:end]
	quotedStr = strings.TrimSpace(quotedStr)
	quoted, _ := hex.DecodeString(quotedStr)
	sigStr := resultStr[strings.Index(resultStr, "sig:")+4:]
	sigStr = strings.TrimSpace(sigStr)
	sig, _ := hex.DecodeString(sigStr)
	return quoted, sig, nil
}

func PCRVerify(quoted []byte) error {
	//compare last 44 bytes
	//integraty that can be compared
	inpcr := quoted[(len(quoted) - 44):]
	// log.Printf("inpcr=%x, length=%d", inpcr, len(inpcr))
	for _, pcr := range Config.PCRs {
		pcrValue := FromHex(pcr)
		// log.Printf("pcr  =%x, length=%d", pcrValue, len(pcrValue))
		// log.Printf("String equals = %v", pcr == Hex(inpcr))
		if bytes.Equal(inpcr, pcrValue) {
			log.Println("PCRVerify success!")
			return nil
		}
	}
	return ErrPCRQuoteInfo
}

func SignatureVerify(pubKey *ecdsa.PublicKey, signature []byte, quoted []byte) error {

	var esig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signature, &esig); err != nil {
		log.Printf("error signature: %x", signature)
		return err
	}
	hash := sha256.Sum256(quoted)

	if !ecdsa.Verify(pubKey, hash[:], esig.R, esig.S) {
		return ErrECDSAVerification
	}
	log.Println("SignatureVerify success!")
	return nil
}

func CertificateVerify(certPEM []byte) error {
	file := path.Join(pcrPath, "ca.cert.pem")
	rootPEM, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		return errors.New("failed to parse root certificate")
	}
	// block, _ := pem.Decode([]byte(certPEM))
	// if block == nil {
	// 	return errors.New("failed to parse certificate PEM")
	// }
	cert, err := x509.ParseCertificate(certPEM)
	if err != nil {
		return errors.New("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "truxen.org",
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return errors.New("failed to verify certificate: " + err.Error())
	}
	log.Println("CertificateVerify success!")
	return nil
}

// Parse PEM encoded PKCS1 or PKCS8 certificate
func ParseECPublicKeyFromCertBlockBytes(certB []byte) (*ecdsa.PublicKey, error) {
	var parsedKey interface{}
	if cert, err := x509.ParseCertificate(certB); err == nil {
		parsedKey = cert.PublicKey
	} else {
		return nil, err
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, ErrNotECPublicKey
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseECPublicKeyFromBlockBytes(key []byte) (*ecdsa.PublicKey, error) {
	var err error

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(key); err != nil {
		return nil, err
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return nil, ErrNotECPublicKey
	}

	return pkey, nil
}

func GetPubKeyBytes() ([]byte, error) {
	file := path.Join(pcrPath, "public.ecc.pem")
	key, err := ioutil.ReadFile(file)
	if err != nil {
		log.Println("opening file: ", file)
		return nil, err
	}
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrMustBePEMEncoded
	}
	return block.Bytes, nil
}

func GetCertBytes() ([]byte, error) {
	file := path.Join(pcrPath, "cert.pem")
	key, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrMustBePEMEncoded
	}
	return block.Bytes, nil
}

func GetPubKey() (*ecdsa.PublicKey, error) {
	pem, err := GetPubKeyBytes()
	if err != nil {
		return nil, err
	}
	key, err := ParseECPublicKeyFromBlockBytes(pem)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func EncodePublicKeyPEM(publicKey *ecdsa.PublicKey) []byte {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return pemEncoded
}

func EncodePrivateKeyPEM(privateKey *ecdsa.PrivateKey) []byte {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded
}

//not work
func GenerateKeyPairP256() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("private.ecc.pem", EncodePrivateKeyPEM(key), 0644)
	if err != nil {
		panic(err)
	}
	publicKey := &key.PublicKey
	err = ioutil.WriteFile("public.ecc.pem", EncodePublicKeyPEM(publicKey), 0644)
	if err != nil {
		panic(err)
	}
}

func WritePrivateKeyPEM(key *ecdsa.PrivateKey) {
	err := ioutil.WriteFile("private.ecc.pem", EncodePrivateKeyPEM(key), 0644)
	if err != nil {
		panic(err)
	}
}

func LoadPrivateKeyFromPEM() (*ecdsa.PrivateKey, error) {
	var err error
	file, err := ioutil.ReadFile("private.ecc.pem")
	if err != nil {
		return nil, err
	}
	var block *pem.Block
	if block, _ = pem.Decode(file); block == nil {
		return nil, ErrMustBePEMEncoded
	}
	der := block.Bytes
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, ErrNotECPrivateKey
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("Failed to load private key")
}

func LoadKeyPairFromPEM() (pub, priv []byte, err error) {
	key, err := LoadPrivateKeyFromPEM()
	if err != nil {
		return nil, nil, err
	}
	pubkey := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	return pubkey, math.PaddedBigBytes(key.D, 32), nil
}
