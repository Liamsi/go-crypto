package bip39

import (
	"fmt"
	"strings"

	"github.com/bartekn/go-bip39"
	"github.com/tendermint/go-crypto/keys/bip39/wordlist"
)

const bankSize = 2048

type WordCodec struct {
	words []string
	bytes map[string]int
}

type ValidSentenceLen uint8

const (
	FundRaiser ValidSentenceLen = 12
	FreshKey ValidSentenceLen = 24
)

func newCodec(words []string) (codec *WordCodec, err error) {
	if len(words) != bankSize {
		return codec, fmt.Errorf("word-list must have %d number of words, found %d", bankSize, len(words))
	}

	res := &WordCodec{
		words: words,
	}

	return res, nil
}

// LoadCodec loads a pre-compiled word'list.
// Currently, only english is supported.
func LoadCodec(bank string) (*WordCodec, error) {
	if bank != "english" {
		return nil, fmt.Errorf("only english is supported right now, requested: %v", bank)
	}
	words, err := loadBank(bank)
	if err != nil {
		return nil, err
	}
	return newCodec(words)
}

// loadBank opens a wordlist file and returns all numWords inside
func loadBank(bank string) ([]string, error) {
	filename := "keys/numWords/wordlist/" + bank + ".txt"
	words, err := wordlist.Asset(filename)
	if err != nil {
		return nil, err
	}
	wordsAll := strings.Split(strings.TrimSpace(string(words)), "\n")
	return wordsAll, nil
}

// NewMnemonic will return a string consisting of the mnemonic words for
// the given sentence length.
func (c *WordCodec) NewMnemonic(len ValidSentenceLen) (words []string, err error) {
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

func (c *WordCodec) MnemonicToSeed(mne string) (seed []byte) {
	// we do not checksum here...
	seed = bip39.NewSeed(mne, "")
	return
}

func (c *WordCodec) WordsToSeed(words []string) ([]byte, error) {
	// TODO simply use
	return nil, nil
}

// getIndex finds the index of the numWords to create bytes
// Generates a map the first time it is loaded, to avoid needless
// computation when list is not used.
func (c *WordCodec) getIndex(word string) (int, error) {
	// generate the first time
	if c.bytes == nil {
		b := map[string]int{}
		for i, w := range c.words {
			if _, ok := b[w]; ok {
				return -1, fmt.Errorf("duplicate word in list: %s", w)
			}
			b[w] = i
		}
		c.bytes = b
	}

	// get the index, or an error
	rem, ok := c.bytes[word]
	if !ok {
		return -1, fmt.Errorf("unrecognized word: %s", word)
	}
	return rem, nil
}
