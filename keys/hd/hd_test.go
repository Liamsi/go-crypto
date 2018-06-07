package hd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tyler-smith/go-bip39"

	"github.com/tendermint/go-crypto"
)

type addrData struct {
	Mnemonic string
	Master   string
	Seed     string
	Priv     string
	Pub      string
	Addr     string
}

// NOTE: atom fundraiser address
// var hdPath string = "m/44'/118'/0'/0/0"
var hdToAddrTable []addrData

func init() {

	b, err := ioutil.ReadFile("test.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = json.Unmarshal(b, &hdToAddrTable)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func TestFundraiserCompatibility(t *testing.T) {

	for i, d := range hdToAddrTable {
		privB, _ := hex.DecodeString(d.Priv)
		pubB, _ := hex.DecodeString(d.Pub)
		addrB, _ := hex.DecodeString(d.Addr)
		seedB, _ := hex.DecodeString(d.Seed)
		masterB, _ := hex.DecodeString(d.Master)

		seed := bip39.NewSeed(d.Mnemonic, "")

		//fmt.Println("================================")
		//fmt.Println("ROUND:", i, "MNEMONIC:", d.Mnemonic)

		master, ch := ComputeMastersFromSeed(seed)
		priv := DerivePrivateKeyForPath(master, ch, "44'/118'/0'/0/0")
		pub := crypto.PrivKeySecp256k1(priv).PubKey()

		//fmt.Printf("\tNODEJS GOLANG\n")
		//fmt.Printf("SEED \t%X %X\n", seedB, seed)
		//fmt.Printf("MSTR \t%X %X\n", masterB, master)
		//fmt.Printf("PRIV \t%X %X\n", privB, priv)
		//fmt.Printf("PUB  \t%X %X\n", pubB, pub)

		assert.Equal(t, seedB, seed)
		assert.Equal(t, master[:], masterB, fmt.Sprintf("Expected masters to match for %d", i))
		assert.Equal(t, priv[:], privB, "Expected priv keys to match")
		var pubBFixed [33]byte
		copy(pubBFixed[:], pubB)
		assert.Equal(t, pub, crypto.PubKeySecp256k1(pubBFixed), fmt.Sprintf("Expected pub keys to match for %d", i))

		addr := pub.Address()
		// fmt.Printf("ADDR  \t%X %X\n", addrB, addr)
		assert.Equal(t, addr, crypto.Address(addrB), fmt.Sprintf("Expected addresses to match %d", i))

	}
}


