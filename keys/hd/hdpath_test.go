package hd

import (
	"fmt"
	"encoding/hex"
	"github.com/tendermint/go-crypto/keys/bip39"
)

func ExampleDerivePrivateKeyForPath() {
	path := NewParams(44, 0, 0, false, 0)
	fmt.Println(path.String())
	// Output: 44'/0'/0'/0/0
}

func ExampleSomeBIP32TestVecs() {

	seed := bip39.MnemonicToSeed("barrel original fuel morning among eternal filter ball stove pluck matrix mechanic")
	master, ch := ComputeMastersFromSeed(seed)
	// cosmos
	priv := DerivePrivateKeyForPath(master, ch, "44'/118'/0'/0/0")
	fmt.Println(hex.EncodeToString(priv[:]))
	// bitcoin
	priv = DerivePrivateKeyForPath(master, ch, "44'/0'/0'/0/0")
	fmt.Println(hex.EncodeToString(priv[:]))
	// ether
	priv = DerivePrivateKeyForPath(master, ch, "44'/60'/0'/0/0")
	fmt.Println(hex.EncodeToString(priv[:]))

	seed = bip39.MnemonicToSeed("advice process birth april short trust crater change bacon monkey medal garment gorilla ranch hour rival razor call lunar mention taste vacant woman sister")
	master, ch = ComputeMastersFromSeed(seed)

	priv = DerivePrivateKeyForPath(master, ch, "44'/1'/1'/0/4")
	fmt.Println(hex.EncodeToString(priv[:]))

	// Output: bfcb217c058d8bbafd5e186eae936106ca3e943889b0b4a093ae13822fd3170c
	// e77c3de76965ad89997451de97b95bb65ede23a6bf185a55d80363d92ee37c3d
	// 7fc4d8a8146dea344ba04c593517d3f377fa6cded36cd55aee0a0bb968e651bc
	// a61f10c5fecf40c084c94fa54273b6f5d7989386be4a37669e6d6f7b0169c163
}