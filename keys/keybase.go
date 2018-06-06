package keys

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/tendermint/go-crypto"
	dbm "github.com/tendermint/tmlibs/db"
	"github.com/tendermint/go-crypto/keys/bip39"
	"github.com/tendermint/go-crypto/keys/hd"
)

// dbKeybase combines encryption and storage implementation to provide
// a full-featured key manager
type dbKeybase struct {
	db    dbm.DB
}

func New(db dbm.DB) dbKeybase {
	return dbKeybase{
		db:    db,
	}
}

// BIP44Prefix is the parts of the BIP32 HD path that are fixed by what we used during the fundraiser.
const BIP44Prefix = "m/44'/118'/"

var _ Keybase = dbKeybase{}

// Create generates a new key and persists it to storage, encrypted
// using the provided password.
// It returns the generated mnemonic and the key Info.
// It returns an error if it fails to
// generate a key for the given algo type, or if another key is
// already stored under the same name.
func (kb dbKeybase) Create(name, language, passwd string, algo CryptoAlgo) (info *Info, mnemonic string, err error) {
	if algo != AlgoSecp256k1 {
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
	// TODO(ismail): use seed to create a key
	hd.ComputeMastersFromSeed(seed)
	return
}

// Recover converts a seedphrase to a private key and persists it,
// encrypted with the given passphrase.  Functions like Create, but
// seedphrase is input not output.
func (kb dbKeybase) Recover(name, passphrase, seedphrase string) (Info, error) {

	return Info{}, nil
}

// List returns the keys from storage in alphabetical order.
func (kb dbKeybase) List() ([]Info, error) {
	var res []Info
	iter := kb.db.Iterator(nil, nil)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		// key := iter.Key()
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

	kb.writeKey(key, name, newpass)
	return nil
}

func (kb dbKeybase) writePubKey(pub crypto.PubKey, name string) Info {
	// make Info
	info := newInfo(name, pub, "")

	// write them both
	kb.db.SetSync(infoKey(name), info.bytes())
	return info
}

func (kb dbKeybase) writeKey(priv crypto.PrivKey, name, passphrase string) Info {
	// generate the encrypted privkey
	privArmor := encryptArmorPrivKey(priv, passphrase)
	// make Info
	info := newInfo(name, priv.PubKey(), privArmor)

	// write them both
	kb.db.SetSync(infoKey(name), info.bytes())
	return info
}

func generate(algo CryptoAlgo, secret []byte) (crypto.PrivKey, error) {
	switch algo {
	case AlgoEd25519:
		return crypto.GenPrivKeyEd25519FromSecret(secret), nil
	case AlgoSecp256k1:
		return crypto.GenPrivKeySecp256k1FromSecret(secret), nil
	default:
		err := errors.Errorf("Cannot generate keys for algorithm: %s", algo)
		return nil, err
	}
}

func infoKey(name string) []byte {
	return []byte(fmt.Sprintf("%s.info", name))
}
