package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	_ "math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/truxen-org/chainpoc/crypto/secp256k1"
	"github.com/truxen-org/chainpoc/txn"
	"github.com/truxen-org/chainpoc/txnchain"
	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
	"github.com/truxen-org/chainpoc/txnwire"
)

type Console struct {
	db    *txndb.MemDatabase
	trie  *txnutil.Trie
	txn   *txn.Txn
	miner *Miner
}

func NewConsole(s *txn.Txn) *Console {
	db, _ := txndb.NewMemDatabase()
	trie := txnutil.NewTrie(db, "")

	return &Console{db: db, trie: trie, txn: s}
}

func (i *Console) SetMiner(m *Miner) {
	i.miner = m
}

func (i *Console) ValidateInput(action string, argumentLength int) error {
	err := false
	var expArgCount int
	switch {
	case action == "update" && argumentLength != 2:
		err = true
		expArgCount = 2
	case action == "get" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "dag" && argumentLength != 2:
		err = true
		expArgCount = 2
	case action == "decode" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "encode" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "gettx" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "tx" && argumentLength != 2:
		err = true
		expArgCount = 2
	case action == "getaddr" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "contract" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "say" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "addp" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "block" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "ca" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "b" && argumentLength != 1:
		err = true
		expArgCount = 1
	case action == "a" && argumentLength != 1:
		err = true
		expArgCount = 1
	}

	if err {
		return errors.New(fmt.Sprintf("'%s' requires %d args, got %d", action, expArgCount, argumentLength))
	} else {
		return nil
	}
}

func (i *Console) PrintRoot() {
	root := txnutil.NewValue(i.trie.Root)
	if len(root.Bytes()) != 0 {
		fmt.Println(hex.EncodeToString(root.Bytes()))
	} else {
		fmt.Println(i.trie.Root)
	}
}

func (i *Console) ParseInput(input string) bool {
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(bufio.ScanWords)

	count := 0
	var tokens []string
	for scanner.Scan() {
		count++
		tokens = append(tokens, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading input:", err)
	}

	if len(tokens) == 0 {
		return true
	}

	err := i.ValidateInput(tokens[0], count-1)
	if err != nil {
		fmt.Println(err)
	} else {
		switch tokens[0] {
		case "update":
			i.trie.Update(tokens[1], tokens[2])

			i.PrintRoot()
		case "get":
			fmt.Println(i.trie.Get(tokens[1]))
		case "root":
			i.PrintRoot()
		case "rawroot":
			fmt.Println(i.trie.Root)
		case "print":
			txndb.DB.Print()
		case "printm": //memdb
			i.db.Print()
		case "decode":
			value := txnutil.NewValueFromBytes([]byte(tokens[1]))
			fmt.Println(value)
		case "a":
			encoded, _ := hex.DecodeString(tokens[1])
			addr := i.txn.BlockManager.BlockChain().CurrentBlock.GetAddr(encoded)
			fmt.Println("addr:", addr)
		case "block":
			encoded, _ := hex.DecodeString(tokens[1])
			block := i.txn.BlockManager.BlockChain().GetBlock(encoded)
			fmt.Println(block)
		case "n":
			num, err := strconv.ParseUint(tokens[1], 0, 0)
			if err != nil {
				fmt.Println(err)
			}
			block := i.txn.BlockManager.BlockChain().GetBlockByNumber(num)
			fmt.Println(block)
		case "p":
			i.txn.BlockManager.BlockChain().PrintLocalChain()
		case "say":
			i.txn.Broadcast(txnwire.MsgTalkTy, []interface{}{tokens[1]})
		case "addp":
			i.txn.ConnectToPeer(tokens[1])
		case "pcount":
			fmt.Println("peers:", i.txn.Peers().Len())
		case "encode":
			fmt.Printf("%q\n", txnutil.Encode(tokens[1]))
		case "tx":
			recipient, err := hex.DecodeString(tokens[1])
			if err != nil {
				fmt.Println("recipient err:", err)
			} else {
				tx := txnchain.NewTransaction(recipient, txnutil.Big(tokens[2]), []string{""})
				data, _ := txndb.DB.Get([]byte("KeyRing"))
				keyRing := txnutil.NewValueFromBytes(data)
				coinbase := i.txn.BlockManager.BlockChain().CurrentBlock.GetAddr(keyRing.Get(1).Bytes()) //always send transaction from coinbase account for PoC purpose
				tx.Nonce = coinbase.Nonce
				tx.Sign(keyRing.Get(0).Bytes())//sign tx with private key
				fmt.Printf("%x\n", tx.Hash())
				i.txn.TxPool.QueueTransaction(tx)
			}
		case "gettx":
			addr, _ := hex.DecodeString(tokens[1])
			data, _ := txndb.DB.Get(addr)
			if len(data) != 0 {
				decoder := txnutil.NewValueFromBytes(data)
				fmt.Println(decoder)
			} else {
				fmt.Println("gettx: tx not found")
			}
		case "contract":
			contract := txnchain.NewTransaction([]byte{}, txnutil.Big(tokens[1]), []string{"PUSH", "1234"})
			fmt.Printf("%x\n", contract.Hash())

			i.txn.TxPool.QueueTransaction(contract)
		case "exit", "quit", "q":
			i.txn.Stop()
			// return false
		case "help":
			fmt.Printf("COMMANDS:\n" +
				"\033[1m= DB =\033[0m\n" +
				"update KEY VALUE - Updates/Creates a new value for the given key\n" +
				"get KEY - Retrieves the given key\n" +
				"root - Prints the hex encoded merkle root\n" +
				"rawroot - Prints the raw merkle root\n" +
				"block HASH - Prints the block\n" +
				"getaddr ADDR - Prints the account associated with the address\n" +
				"\033[1m= Dagger =\033[0m\n" +
				"dag HASH NONCE - Verifies a nonce with the given hash with dagger\n" +
				"\033[1m= Encoding =\033[0m\n" +
				"decode STR\n" +
				"encode STR\n" +
				"\033[1m= Other =\033[0m\n" +
				"addp HOST:PORT\n" +
				"tx TO AMOUNT\n" +
				"contract AMOUNT\n" +
				"mine - start miner\n" +
				"mine1 - mine a block\n" +
				"abort - stop miner\n")

		case "m": //start mining
			if i.miner != nil {
				log.Println("Starting miner...")
				i.miner.Start()
			} else {
				log.Println("Not a miner node.")
			}
		case "s": //stop mining
			if i.miner != nil {
				i.miner.Stop()
				log.Println("Stoping miner...")
			}
		case "ca": //create test addresses
			s := tokens[1]
			num, err := strconv.Atoi(s)
			if err != nil {
				fmt.Println(err)
				break
			}
			log.Printf("creating %d accounts ... ", num)
			txtPath := path.Join(txnutil.Config.BaseDir, "b"+s+".txt")
			fileHandle, _ := os.Create(txtPath)
			writer := bufio.NewWriter(fileHandle)
			for i := 0; i < num; i++ {
				pub, _ := secp256k1.GenerateKeyPair()
				addr := txnutil.Sha3Bin(pub[1:])[12:]
				addrHex := hex.EncodeToString(addr)
				// log.Printf("%s", addrHex)
				fmt.Fprintln(writer, addrHex)
			}
			writer.Flush()
			fileHandle.Close()
			log.Println("//////////create accounts done.")
		case "b": //test creating batch transaction and sending out
			s := tokens[1]
			num, err := strconv.Atoi(s)
			if err != nil {
				fmt.Println(err)
				break
			}
			data, _ := txndb.DB.Get([]byte("KeyRing"))
			keyRing := txnutil.NewValueFromBytes(data)
			coinbase := keyRing.Get(1).Bytes()
			privateKey := keyRing.Get(0).Bytes()
			amB := txnutil.Big("10000")
			log.Printf("sending %d txs ... value %v", num, amB)
			txtPath := path.Join(txnutil.Config.BaseDir, "b"+s+".txt")
			file, err := os.Open(txtPath)
			if err != nil {
				log.Printf("input error %v", err)
				break
			}
			scanner := bufio.NewScanner(file)
			n := 0
			var wg sync.WaitGroup
			// signedCh := make(chan *txnchain.Transaction)
			// start := time.Now()
			// go func() {
			// 	for {

			// 		signedTx := <-signedCh
			// 		// fmt.Printf(">>>>>>>>>>>>>>>>>received  %x:  \n", signedTx.Hash())

			// 		i.txn.TxPool.QueueTransaction(signedTx)
			// 	}
			// 	wg.Wait()
			// }()
			for scanner.Scan() {
				line := scanner.Text() //load a address from addresses file
				recipient, err := hex.DecodeString(line)
				if err != nil {
					log.Printf("input error %v", err)
					continue
				}
				tx := txnchain.NewTransaction(recipient, amB, []string{""})
				coinbaseAccount := i.txn.BlockManager.BlockChain().CurrentBlock.GetAddr(coinbase)
				tx.Nonce = coinbaseAccount.Nonce
				// startS := time.Now()

				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					tx.Sign(privateKey)
					// fmt.Printf(">>>>>>>>>>>>>>>>>send %d %x \n", n, tx.Hash())
					// signedCh <- tx
					i.txn.TxPool.QueueTransaction(tx)
				}(n)
				// tx.Sign(privateKey)
				// i.txn.TxPool.QueueTransaction(tx)
				// fmt.Printf("Sign uses %v \n", time.Since(startS))
				// fmt.Printf("%d %x: %s >> %s\n", n, tx.Hash(), amount, line)
				n += 1
				time.Sleep(time.Second)
			}
			// fmt.Println(">>>>>>>>>>>>>>>>>>Sign Transactions ", time.Since(start))
			if err := scanner.Err(); err != nil {
				log.Printf("input error %v", err)
				break
			}
			// go func() {
			// 	for signedTx := range signedCh {

			// 		i.txn.TxPool.QueueTransaction(signedTx)
			// 	}

			// }()
			wg.Wait()
			// fmt.Println(">>>>>>>>>>>>>>>>>QueueTransaction ", time.Since(start)) //not show up

			file.Close()

		case "ps": //propose miner join request
			//TODO DC from CA
			q, s, _, sr := showMinerInfo(false)
			c, _ := txnutil.GetCertBytes()
			pr := &txnchain.ProposalRequest{
				Quoted:      q,
				Signature:   s,
				Certificate: c,
				Prop: &txnchain.Proposal{
					Signer: txnutil.FromHex(sr),
					Nonce:  txnchain.NonceAuthVote,
				},
			}
			i.txn.Broadcast(txnwire.MsgPropTy, []interface{}{pr.RlpValueEncode()})
			log.Println("propose:", pr)
			log.Println("proposed signer:", sr)
		case "i":
			showMinerInfo(true)
		default:
			fmt.Println("Unknown command:", tokens[0])
		}
	}

	return true
}

func (i *Console) Start() {
	fmt.Printf("Type (help) for help\n")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("$ >>> ")
		str, _, err := reader.ReadLine()
		if err != nil {
			fmt.Println("Error reading input", err)
		} else {
			if !i.ParseInput(string(str)) {
				return
			}
		}
	}
}
