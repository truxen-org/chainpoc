package txnutil

import (
	"encoding/json"
	"log"
	"os"
)

// Config struct isn't exposed
type config struct {
	Ver             string   `json:"Ver"`
	BaseDir         string   `json:"BaseDir"`
	OutboundPort    int      `json:"OutboundPort"`
	Debug           bool     `json:"Debug"`
	IsMiner         bool     `json:"IsMiner"`
	PCRs            []string `json:"PCRs"` //TPMS_QUOTE_INFO
	Signers         []string `json:"Signers"`
	DBCache         int      `json:"DBCache"`
	NodeCache       int      `json:"NodeCache"`
	Profile         bool     `json:"Profile"`
	StartMining     bool     `json:"StartMining"`
	StartMiningOnTx bool     `json:"StartMiningOnTx"`
	GenAddr         bool     `json:"GenAddr"`
	UseUPnP         bool     `json:"UseUPnP"`
	UseSeed         bool     `json:"UseSeed"`
	DefautPeer      string   `json:"DefautPeer"`
	ConnectPeer     string   `json:"ConnectPeer"`
}

var Config *config

func LoadConfiguration(file string) {
	log.Println("config=", file)
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		log.Fatal(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&Config)
}

func SaveConfiguration() {
	configFile, err := os.OpenFile("config.json", os.O_WRONLY, os.ModePerm)
	defer configFile.Close()
	if err != nil {
		log.Fatal(err.Error())
	}
	jsonEnc := json.NewEncoder(configFile)
	jsonEnc.SetIndent("", "    ")
	err = jsonEnc.Encode(&Config)
	if err != nil {
		log.Fatal(err.Error())
	}
}
