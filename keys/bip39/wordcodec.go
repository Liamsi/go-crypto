package bip39

import (
	"strings"

	"github.com/bartekn/go-bip39"
)

type ValidSentenceLen uint8

const (
	FundRaiser ValidSentenceLen = 12
	FreshKey ValidSentenceLen = 24
)

// NewMnemonic will return a string consisting of the mnemonic words for
// the given sentence length.
func NewMnemonic(len ValidSentenceLen) (words []string, err error) {
	// len = (ENT + checksum) / 11
	var ENT int
	switch len {
	case FundRaiser:
		ENT = 128
	case FreshKey:
		ENT = 256
	}
	var entropy []byte
	entropy, err = bip39.NewEntropy(ENT)
	if err != nil {
		return
	}
	var mnemonic string
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		return
	}
	// TODO(ismail): we have to be careful with the seperator in other languages here:
	words = strings.Split(mnemonic, " ")
	return
}

func MnemonicToSeed(mne string) (seed []byte) {
	// we do not checksum here...
	seed = bip39.NewSeed(mne, "")
	return
}


