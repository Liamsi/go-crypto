package keys

import (
	crypto "github.com/tendermint/go-crypto"
	"github.com/tendermint/go-crypto/keys/hd"
)

// Keybase allows simple CRUD on a keystore, as an aid to signing
type Keybase interface {
	// Sign some bytes
	Sign(name, passwd string, msg []byte) (crypto.Signature, crypto.PubKey, error)
	// CreateMnemonic a new keypair
	CreateMnemonic(name string, language Language, passwd string, algo CryptoAlgo) (info *Info, seed string, err error)
	// CreateFundraiserKey takes a seedphrase and loads in the key
	CreateFundraiserKey(name, mnemonic, seedphrase string) (info *Info, err error)
	// Derive derives a key from the passed mnemonic using a BIP44 path.
	Derive(name, mnemonic, passwd string, params hd.BIP44Params) (*Info, error)
	List() ([]Info, error)
	Get(name string) (*Info, error)
	Update(name, oldpass, newpass string) error
	Delete(name, passphrase string) error

	Import(name string, armor string) (err error)
	ImportPubKey(name string, armor string) (err error)
	Export(name string) (armor string, err error)
	ExportPubKey(name string) (armor string, err error)
}

// Info is the public information about a key
type Info struct {
	Name         string        `json:"name"`
	PubKey       crypto.PubKey `json:"pubkey"`
	PrivKeyArmor string        `json:"privkey.armor"`
}

func newInfo(name string, pub crypto.PubKey, privArmor string) Info {
	return Info{
		Name:         name,
		PubKey:       pub,
		PrivKeyArmor: privArmor,
	}
}

// Address is a helper function to calculate the address from the pubkey
func (i Info) Address() []byte {
	return i.PubKey.Address()
}

func (i Info) bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(i)
	if err != nil {
		panic(err)
	}
	return bz
}

func readInfo(bz []byte) (info *Info, err error) {
	info = &Info{}
	err = cdc.UnmarshalBinaryBare(bz, info)
	return
}
