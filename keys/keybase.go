package keys

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/tendermint/go-crypto"
	"github.com/tendermint/go-crypto/keys/bip39"
	"github.com/tendermint/go-crypto/keys/hd"
	dbm "github.com/tendermint/tmlibs/db"
)

var _ Keybase = dbKeybase{}

// Language is a language to create the BIP 39 mnemonic in.
// Currently, only english is supported though.
// Find a list of all supported languages in the BIP 39 spec (word lists).
type Language int

const (
	// English is the default language to create a mnemonic.
	// It is the only supported language by this package.
	English Language = iota
	// Japanese is currently not supported.
	Japanese
	// Korean is currently not supported.
	Korean
	// Spanish is currently not supported.
	Spanish
	// ChineseSimplified is currently not supported.
	ChineseSimplified
	// ChineseTraditional is currently not supported.
	ChineseTraditional
	// French is currently not supported.
	French
	// Italian is currently not supported.
	Italian
)

// dbKeybase combines encryption and storage implementation to provide
// a full-featured key manager
type dbKeybase struct {
	db dbm.DB
}

// New creates a new keybase instance using the passed DB for reading and writing keys.
func New(db dbm.DB) Keybase {
	return dbKeybase{
		db: db,
	}
}

// CreateMnemonic generates a new key and persists it to storage, encrypted
// using the provided password.
// It returns the generated mnemonic and the key Info.
// It returns an error if it fails to
// generate a key for the given algo type, or if another key is
// already stored under the same name.
func (kb dbKeybase) CreateMnemonic(name string, language Language, passwd string, algo SigningAlgo) (info *Info, mnemonic string, err error) {
	if language != English {
		return nil, "", fmt.Errorf("unsupported language: currently only english is supported")
	}
	if algo != Secp256k1 {
		err = fmt.Errorf("currently only Secp256k1 are supported as required by bip39/bip44, requested %s", algo)
		return
	}

	// default number of words (24):
	mnemonicS, err := bip39.NewMnemonic(bip39.FreshKey)
	if err != nil {
		return
	}
	// TODO(ismail): we have to be careful with the separator in non-ltr languages. Ideally, our package should provide
	// a helper function for that
	mnemonic = strings.Join(mnemonicS, " ")
	seed := bip39.MnemonicToSeed(mnemonic)
	info, err = kb.persistDerivedKey(seed, passwd, name, hd.FullFundraiserPath)
	return
}

// CreateFundraiserKey converts a mnemonic to a private key and persists it,
// encrypted with the given passphrase.  Functions like CreateMnemonic, but
// seedphrase is input not output.
func (kb dbKeybase) CreateFundraiserKey(name, mnemonic, passwd string) (info *Info, err error) {
	words := strings.Split(mnemonic, " ")
	if len(words) != 12 {
		err = fmt.Errorf("recovering only works with 12 word (fundraiser) mnemonics, got: %v words", len(words))
		return
	}
	seed, err := bip39.MnemonicToSeedWithErrChecking(mnemonic)
	if err != nil {
		return
	}
	info, err = kb.persistDerivedKey(seed, passwd, name, hd.FullFundraiserPath)
	return
}

func (kb dbKeybase) Derive(name, mnemonic, passwd string, params hd.BIP44Params) (info *Info, err error) {
	seed, err := bip39.MnemonicToSeedWithErrChecking(mnemonic)
	if err != nil {
		return
	}
	info, err = kb.persistDerivedKey(seed, passwd, name, params.String())

	return
}

func (kb *dbKeybase) persistDerivedKey(seed []byte, passwd, name, fullHdPath string) (info *Info, err error) {
	// create master key and derive first key:
	masterPriv, ch := hd.ComputeMastersFromSeed(seed)
	derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, fullHdPath)
	if err != nil {
		return
	}

	// if we have a password, use it to encrypt the private key and store it
	// else store the public key only
	if passwd != "" {
		inf := kb.writePrivKey(crypto.PrivKeySecp256k1(derivedPriv), name, passwd)
		info = &inf
	} else {
		inf := kb.writePubKey(crypto.PrivKeySecp256k1(derivedPriv).PubKey(), name)
		info = &inf
	}
	return
}

// List returns the keys from storage in alphabetical order.
func (kb dbKeybase) List() ([]Info, error) {
	var res []Info
	iter := kb.db.Iterator(nil, nil)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		info, err := readInfo(iter.Value())
		if err != nil {
			return nil, err
		}
		res = append(res, *info)
	}
	return res, nil
}

// Get returns the public information about one key.
func (kb dbKeybase) Get(name string) (*Info, error) {
	bs := kb.db.Get(infoKey(name))
	return readInfo(bs)
}

// Sign signs the msg with the named key.
// It returns an error if the key doesn't exist or the decryption fails.
func (kb dbKeybase) Sign(name, passphrase string, msg []byte) (sig crypto.Signature, pub crypto.PubKey, err error) {
	info, err := kb.Get(name)
	if err != nil {
		return
	}
	if info.PrivKeyArmor == "" {
		err = fmt.Errorf("private key not available")
		return
	}
	priv, err := unarmorDecryptPrivKey(info.PrivKeyArmor, passphrase)
	if err != nil {
		return
	}
	sig = priv.Sign(msg)
	pub = priv.PubKey()
	return
}

func (kb dbKeybase) Export(name string) (armor string, err error) {
	bz := kb.db.Get(infoKey(name))
	if bz == nil {
		return "", errors.New("No key to export with name " + name)
	}
	return armorInfoBytes(bz), nil
}

// ExportPubKey returns public keys in ASCII armored format.
// Retrieve a Info object by its name and return the public key in
// a portable format.
func (kb dbKeybase) ExportPubKey(name string) (armor string, err error) {
	bz := kb.db.Get(infoKey(name))
	if bz == nil {
		return "", errors.New("No key to export with name " + name)
	}
	info, err := readInfo(bz)
	if err != nil {
		return
	}
	return armorPubKeyBytes(info.PubKey.Bytes()), nil
}

func (kb dbKeybase) Import(name string, armor string) (err error) {
	bz := kb.db.Get(infoKey(name))
	if len(bz) > 0 {
		return errors.New("Cannot overwrite data for name " + name)
	}
	infoBytes, err := unarmorInfoBytes(armor)
	if err != nil {
		return
	}
	kb.db.Set(infoKey(name), infoBytes)
	return nil
}

// ImportPubKey imports ASCII-armored public keys.
// Store a new Info object holding a public key only, i.e. it will
// not be possible to sign with it as it lacks the secret key.
func (kb dbKeybase) ImportPubKey(name string, armor string) (err error) {
	bz := kb.db.Get(infoKey(name))
	if len(bz) > 0 {
		return errors.New("Cannot overwrite data for name " + name)
	}
	pubBytes, err := unarmorPubKeyBytes(armor)
	if err != nil {
		return
	}
	pubKey, err := crypto.PubKeyFromBytes(pubBytes)
	if err != nil {
		return
	}
	kb.writePubKey(pubKey, name)
	return
}

// Delete removes key forever, but we must present the
// proper passphrase before deleting it (for security).
func (kb dbKeybase) Delete(name, passphrase string) error {
	// verify we have the proper password before deleting
	info, err := kb.Get(name)
	if err != nil {
		return err
	}
	_, err = unarmorDecryptPrivKey(info.PrivKeyArmor, passphrase)
	if err != nil {
		return err
	}
	kb.db.DeleteSync(infoKey(name))
	return nil
}

// Update changes the passphrase with which an already stored key is
// encrypted.
//
// oldpass must be the current passphrase used for encryption,
// newpass will be the only valid passphrase from this time forward.
func (kb dbKeybase) Update(name, oldpass, newpass string) error {
	info, err := kb.Get(name)
	if err != nil {
		return err
	}
	key, err := unarmorDecryptPrivKey(info.PrivKeyArmor, oldpass)
	if err != nil {
		return err
	}

	kb.writePrivKey(key, name, newpass)
	return nil
}

func (kb dbKeybase) writePubKey(pub crypto.PubKey, name string) Info {
	// make Info
	info := newInfo(name, pub, "")

	// write them both
	kb.db.SetSync(infoKey(name), info.bytes())
	return info
}

func (kb dbKeybase) writePrivKey(priv crypto.PrivKey, name, passpwd string) Info {
	// generate the encrypted privkey
	privArmor := encryptArmorPrivKey(priv, passpwd)
	// make Info
	info := newInfo(name, priv.PubKey(), privArmor)

	// write them both
	kb.db.SetSync(infoKey(name), info.bytes())
	return info
}

func infoKey(name string) []byte {
	return []byte(fmt.Sprintf("%s.info", name))
}
