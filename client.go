package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"strings"
	"time"

	_ "net/http/pprof"
	"os"
	"os/signal"

	"github.com/truxen-org/chainpoc/crypto/secp256k1"
	"github.com/truxen-org/chainpoc/txn"
	"github.com/truxen-org/chainpoc/txnchain"
	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
)

type logWriter struct {
}

func GoID() string {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	return idField
}
func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().Local().Format("15:04:05.999") + " " + GoID() + " " + string(bytes))
}

func init() {

	log.SetFlags(0)
	log.SetOutput(new(logWriter))
}

// Register interrupt handlers so we can stop the txn
func RegisterInterupts(s *txn.Txn) {
	// Buffered chan of one is enough
	c := make(chan os.Signal, 1)
	// Notify about interrupts for now
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Printf("Shutting down (%v) ... \n", sig)
			s.Stop()
		}
	}()
}

func getCoinbase() []byte {
	data, err := txndb.DB.Get([]byte("KeyRing"))
	if err != nil {
		return nil
	}
	keyRing := txnutil.NewValueFromBytes(data)
	addr := keyRing.Get(1).Bytes()
	return addr
}

func CreateKeyPair() {
	fmt.Println(`Generating new address and keypair.`)
	pub, prv := secp256k1.GenerateKeyPair()
	addr := txnutil.Sha3Bin(pub[1:])[12:]
	keyRing := txnutil.NewValue([]interface{}{prv, addr, pub[1:]})
	txndb.DB.Put([]byte("KeyRing"), keyRing.Encode())
	showKeyRing()
}

func showKeyRing() {
	data, _ := txndb.DB.Get([]byte("KeyRing"))
	keyRing := txnutil.NewValueFromBytes(data)
	prv := keyRing.Get(0).Bytes()
	addr := keyRing.Get(1).Bytes()
	pub := keyRing.Get(2).Bytes()
	fmt.Printf(`
	++++++++++++++++ KeyRing +++++++++++++++++++
	addr: %x
	prvk: %x
	pubk: %x
	++++++++++++++++++++++++++++++++++++++++++++
	`, addr, prv, pub)
}

func showMinerInfo(showPCRValue bool) (quoted, signature, pubKey []byte, signer string) {
	if !txnutil.Config.IsMiner {
		log.Println("Not a miner")
		return
	}
	quoted, signature, err := txnutil.PCRSign("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n***************MINER INFO***************")
	fmt.Printf("quoted = %x\n", quoted)
	fmt.Printf("signature = %x\n", signature)
	if showPCRValue {
		pcr := quoted[len(quoted)-44:] //PCR is  part of Quoted named TPMS_QUOTE_INFO
		fmt.Printf("PCR = %x\n", pcr)
	}
	pubKey, err = txnutil.GetPubKeyBytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pubKey = %x\n", pubKey)
	signer = txnchain.SignerFromPubKey(pubKey)
	fmt.Printf("signer = %s\n", signer)
	fmt.Println("*****************************************")
	return
}

//should not be used since CA involved
func regenerateKeys(i int) {
	if !txnutil.Config.IsMiner {
		log.Println("Not a miner")
		return
	}
	if err := os.RemoveAll("./pcr"); err != nil {
		log.Fatal(err)
	}
	log.Println("!!!pcr folder removed!!!")
	txnutil.InitPCR()
	pub, err := txnutil.GetPubKeyBytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PubKey = %x\n", pub)
	signer := txnchain.SignerFromPubKey(pub)
	fmt.Printf("signer = %s\n", signer)
	snrs := txnutil.Config.Signers
	if len(snrs) < i+1 {
		txnutil.Config.Signers = make([]string, i+1)
		copy(txnutil.Config.Signers, snrs)
	}
	txnutil.Config.Signers[i] = signer
	txnutil.SaveConfiguration()

	log.Println("config.json updated!")
}

func main() {
	// go func() {
	// 	log.Println(http.ListenAndServe("localhost:6060", nil))
	// }()
	// runtime.GOMAXPROCS(runtime.NumCPU())

	// f, _ := os.Create("cpuprofile")
	// pprof.StartCPUProfile(f)
	// defer pprof.StopCPUProfile()
	// go func() {
	// 	// http.HandleFunc("/debug/pprof/block", pprof.Index)
	// 	// http.HandleFunc("/debug/pprof/goroutine", pprof.Index)
	// 	http.HandleFunc("/debug/pprof/heap", pprof.Index)
	// 	// http.HandleFunc("/debug/pprof/threadcreate", pprof.Index)

	// 	http.ListenAndServe("0.0.0.0:8888", nil)
	// }()
	// var finishWaiter chan int

	// Init()

	configFile := flag.String("c", "config.json", "config file in json format")
	showPCRInfo := flag.Bool("i", false, "show pcr info")
	// UpdateSigner := flag.Int("r", -1, "recreate pcr keys. specify the signer index of current node.")
	useVSCodeDebug := flag.Bool("debug", false, "config in vs code debug configuration json file; cause ide dead if open console")

	flag.Parse()

	txnutil.LoadConfiguration(*configFile)
	txnutil.InitLogger()
	txndb.InitDB()
	txnchain.InitFees()
	if *showPCRInfo {
		if txnutil.Config.IsMiner {
			txnutil.InitPCR()
			showMinerInfo(true)
		} else {
			log.Println("Not a miner")
		}
		os.Exit(0)
	}
	// if *UpdateSigner > -1 {
	// 	if txnutil.Config.IsMiner {
	// 		regenerateKeys(*UpdateSigner)
	// 	} else {
	// 		log.Println("Not a miner")
	// 	}
	// 	os.Exit(0)
	// }
	var err error
	var key []byte

	if txnutil.Config.IsMiner {
		txnutil.InitPCR()
		key, err = txnutil.GetPubKeyBytes()
		if len(key) == 0 || err != nil {
			log.Fatal("PCR PubKey error: ", err)
		}
	}
	poi := txnchain.NewPoI(key)
	txn0, err := txn.New(poi)
	if err != nil {
		log.Println("eth start err:", err)
		return
	}
	if coinbase := getCoinbase(); coinbase == nil {
		CreateKeyPair()
	}
	if txnutil.Config.GenAddr {
		fmt.Println("This action overwrites your old private key. Are you sure? (y/n)")

		var r string
		fmt.Scanln(&r)
		for ; ; fmt.Scanln(&r) {
			if r == "n" || r == "y" {
				break
			} else {
				fmt.Printf("Yes or no? %s", r)
			}
		}

		if r == "y" {
			CreateKeyPair()
		}
		os.Exit(0)
	}

	log.Printf("Starting v%s\n", txnutil.Config.Ver)

	// err = os.Mkdir(txnutil.Config.BaseDir, os.ModePerm)
	// // Error is OK if the error is ErrExist
	// if err != nil && !os.IsExist(err) {
	// 	log.Panic("Unable to create EXECPATH:", err)
	// }
	var console *Console
	if !*useVSCodeDebug {
		console = NewConsole(txn0)
		go console.Start()
	}

	RegisterInterupts(txn0)

	txn0.Start()

	if txnutil.Config.ConnectPeer != "" {
		txn0.ConnectToPeer(txnutil.Config.ConnectPeer)
	}
	if txnutil.Config.IsMiner {
		txnutil.InitPCR()
		showMinerInfo(false) //PCR value is not correct on the first run
		miner := NewMiner(txn0, poi)
		if console != nil {
			console.SetMiner(miner)
		}
		//mine if txs exist
		if txnutil.Config.StartMiningOnTx {
			txn0.TxPool.Subscribe(miner.txCh)
		}else if txnutil.Config.StartMining {//mine after starting
			log.Println("Starting miner...")
			miner.Start()
			if txn0.Peers().Len() == 0 {
				txn0.CatchingupChan <- false
			}
		}
	}
	// showKeyRing()
	// Wait for shutdown
	txn0.WaitForShutdown()

	// <-finishWaiter

}
