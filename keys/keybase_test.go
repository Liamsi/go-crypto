package keys_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/go-crypto"
	"github.com/tendermint/go-crypto/keys"

	dbm "github.com/tendermint/tmlibs/db"
)

// TestKeyManagement makes sure we can manipulate these keys well
func TestKeyManagement(t *testing.T) {
	// make the storage with reasonable defaults
	cstore := keys.New(
		dbm.NewMemDB(),
	)

	algo := keys.AlgoSecp256k1
	n1, n2, n3 := "personal", "business", "other"
	p1, p2 := "1234", "really-secure!@#$"

	// Check empty state
	l, err := cstore.List()
	require.Nil(t, err)
	assert.Empty(t, l)

	_, _, err = cstore.CreateMnemonic(n1, "english", p1, keys.AlgoEd25519)
	assert.Errorf(t, err, "ed25519 keys are currently not supported by keybase")

	// create some keys
	i, err := cstore.Get(n1)
	fmt.Println(i)
	assert.Error(t, err)
	i, _, err = cstore.CreateMnemonic(n1, "english", p1, algo)

	require.NoError(t, err)
	require.Equal(t, n1, i.Name)
	_, _, err = cstore.CreateMnemonic(n2, "english", p2, algo)
	require.NoError(t, err)

	// we can get these keys
	i2, err := cstore.Get(n2)
	assert.Nil(t, err)
	_, err = cstore.Get(n3)
	assert.NotNil(t, err)

	// list shows them in order
	keyS, err := cstore.List()
	require.NoError(t, err)
	require.Equal(t, 2, len(keyS))
	// note these are in alphabetical order
	assert.Equal(t, n2, keyS[0].Name)
	assert.Equal(t, n1, keyS[1].Name)
	assert.Equal(t, i2.PubKey, keyS[0].PubKey)

	// deleting a key removes it
	err = cstore.Delete("bad name", "foo")
	require.NotNil(t, err)
	err = cstore.Delete(n1, p1)
	require.NoError(t, err)
	keyS, err = cstore.List()
	require.NoError(t, err)
	assert.Equal(t, 1, len(keyS))
	_, err = cstore.Get(n1)
	assert.Error(t, err)

	//make sure that it only signs with the right password
	//tx := mock.NewSig([]byte("mytransactiondata"))
	//err = cstore.Sign(n2, p1, tx)
	//assert.NotNil(t, err)
	//err = cstore.Sign(n2, p2, tx)
	//assert.Nil(t, err, "%+v", err)
	//sigs, err := tx.Signers()
	//assert.Nil(t, err, "%+v", err)
	//if assert.Equal(t, 1, len(sigs)) {
	//	assert.Equal(t, i2.PubKey, sigs[0])
	//}
}

// TestSignVerify does some detailed checks on how we sign and validate
// signatures
func TestSignVerify(t *testing.T) {
	cstore := keys.New(
		dbm.NewMemDB(),
	)
	algo := keys.AlgoSecp256k1

	n1, n2, n3 := "some dude", "a dudette", "dude-ish"
	p1, p2, p3 := "1234", "foobar", "foobar"

	// create two users and get their info
	i1, _, err := cstore.CreateMnemonic(n1, "english", p1, algo)
	require.Nil(t, err)

	i2, _, err := cstore.CreateMnemonic(n2, "english", p2, algo)
	require.Nil(t, err)

	// Import a public key
	armor, err := cstore.ExportPubKey(n2)
	require.Nil(t, err)
	cstore.ImportPubKey(n3, armor)
	i3, err := cstore.Get(n3)
	require.Nil(t, err)
	require.Equal(t, i3.PrivKeyArmor, "")

	// let's try to sign some messages
	d1 := []byte("my first message")
	d2 := []byte("some other important info!")
	d3 := []byte("feels like I forgot something...")

	// try signing both data with both keys...
	s11, pub1, err := cstore.Sign(n1, p1, d1)
	require.Nil(t, err)
	require.Equal(t, i1.PubKey, pub1)

	s12, pub1, err := cstore.Sign(n1, p1, d2)
	require.Nil(t, err)
	require.Equal(t, i1.PubKey, pub1)

	s21, pub2, err := cstore.Sign(n2, p2, d1)
	require.Nil(t, err)
	require.Equal(t, i2.PubKey, pub2)

	s22, pub2, err := cstore.Sign(n2, p2, d2)
	require.Nil(t, err)
	require.Equal(t, i2.PubKey, pub2)

	// let's try to validate and make sure it only works when everything is proper
	cases := []struct {
		key   crypto.PubKey
		data  []byte
		sig   crypto.Signature
		valid bool
	}{
		// proper matches
		{i1.PubKey, d1, s11, true},
		// change data, pubkey, or signature leads to fail
		{i1.PubKey, d2, s11, false},
		{i2.PubKey, d1, s11, false},
		{i1.PubKey, d1, s21, false},
		// make sure other successes
		{i1.PubKey, d2, s12, true},
		{i2.PubKey, d1, s21, true},
		{i2.PubKey, d2, s22, true},
	}

	for i, tc := range cases {
		valid := tc.key.VerifyBytes(tc.data, tc.sig)
		assert.Equal(t, tc.valid, valid, "%d", i)
	}

	// Now try to sign data with a secret-less key
	_, _, err = cstore.Sign(n3, p3, d3)
	assert.NotNil(t, err)
}

func assertPassword(t *testing.T, cstore keys.Keybase, name, pass, badpass string) {
	err := cstore.Update(name, badpass, pass)
	assert.NotNil(t, err)
	err = cstore.Update(name, pass, pass)
	assert.Nil(t, err, "%+v", err)
}

// TestExportImport tests exporting and importing keys.
func TestExportImport(t *testing.T) {

	// make the storage with reasonable defaults
	db := dbm.NewMemDB()
	cstore := keys.New(
		db,
	)

	info, _, err := cstore.CreateMnemonic("john", "passphrase", "english", keys.AlgoSecp256k1)
	assert.Nil(t, err)
	assert.Equal(t, info.Name, "john")
	addr := info.PubKey.Address()

	john, err := cstore.Get("john")
	assert.Nil(t, err)
	assert.Equal(t, john.Name, "john")
	assert.Equal(t, john.PubKey.Address(), addr)

	armor, err := cstore.Export("john")
	assert.Nil(t, err)

	err = cstore.Import("john2", armor)
	assert.Nil(t, err)

	john2, err := cstore.Get("john2")
	assert.Nil(t, err)

	assert.Equal(t, john.PubKey.Address(), addr)
	assert.Equal(t, john.Name, "john")
	assert.Equal(t, john, john2)
}
//
func TestExportImportPubKey(t *testing.T) {
	// make the storage with reasonable defaults
	db := dbm.NewMemDB()
	cstore := keys.New(
		db,
	)

	// CreateMnemonic a private-public key pair and ensure consistency
	notPasswd := "n9y25ah7"
	info, _, err := cstore.CreateMnemonic("john", "english", notPasswd, keys.AlgoSecp256k1)
	assert.Nil(t, err)
	assert.NotEqual(t, info.PrivKeyArmor, "")
	assert.Equal(t, info.Name, "john")
	addr := info.PubKey.Address()
	john, err := cstore.Get("john")
	assert.Nil(t, err)
	assert.Equal(t, john.Name, "john")
	assert.Equal(t, john.PubKey.Address(), addr)

	// Export the public key only
	armor, err := cstore.ExportPubKey("john")
	assert.Nil(t, err)
	// Import it under a different name
	err = cstore.ImportPubKey("john-pubkey-only", armor)
	assert.Nil(t, err)
	// Ensure consistency
	john2, err := cstore.Get("john-pubkey-only")
	assert.Nil(t, err)
	assert.Equal(t, john2.PrivKeyArmor, "")
	// Compare the public keys
	assert.True(t, john.PubKey.Equals(john2.PubKey))
	// Ensure the original key hasn't changed
	john, err = cstore.Get("john")
	assert.Nil(t, err)
	assert.Equal(t, john.PubKey.Address(), addr)
	assert.Equal(t, john.Name, "john")

	// Ensure keys cannot be overwritten
	err = cstore.ImportPubKey("john-pubkey-only", armor)
	assert.NotNil(t, err)
}

// TestAdvancedKeyManagement verifies update, import, export functionality
func TestAdvancedKeyManagement(t *testing.T) {

	// make the storage with reasonable defaults
	cstore := keys.New(
		dbm.NewMemDB(),
	)

	algo := keys.AlgoSecp256k1
	n1, n2 := "old-name", "new name"
	p1, p2 := "1234", "foobar"

	// make sure key works with initial password
	_, _, err := cstore.CreateMnemonic(n1, "english", p1, algo)
	require.Nil(t, err, "%+v", err)
	assertPassword(t, cstore, n1, p1, p2)

	// update password requires the existing password
	err = cstore.Update(n1, "jkkgkg", p2)
	assert.NotNil(t, err)
	assertPassword(t, cstore, n1, p1, p2)

	// then it changes the password when correct
	err = cstore.Update(n1, p1, p2)
	assert.Nil(t, err)
	// p2 is now the proper one!
	assertPassword(t, cstore, n1, p2, p1)

	// exporting requires the proper name and passphrase
	_, err = cstore.Export(n1 + ".notreal")
	assert.NotNil(t, err)
	_, err = cstore.Export(" " + n1)
	assert.NotNil(t, err)
	_, err = cstore.Export(n1 + " ")
	assert.NotNil(t, err)
	_, err = cstore.Export("")
	assert.NotNil(t, err)
	exported, err := cstore.Export(n1)
	require.Nil(t, err, "%+v", err)

	// import succeeds
	err = cstore.Import(n2, exported)
	assert.Nil(t, err)

	// second import fails
	err = cstore.Import(n2, exported)
	assert.NotNil(t, err)
}

// TestSeedPhrase verifies restoring from a seed phrase
func TestSeedPhrase(t *testing.T) {

	// make the storage with reasonable defaults
	cstore := keys.New(
		dbm.NewMemDB(),
	)

	algo := keys.AlgoSecp256k1
	n1, n2 := "lost-key", "found-again"
	p1, p2 := "1234", "foobar"

	// make sure key works with initial password
	info, mnemonic, err := cstore.CreateMnemonic(n1, "english", p1, algo)
	require.Nil(t, err, "%+v", err)
	assert.Equal(t, n1, info.Name)
	assert.NotEmpty(t, mnemonic)

	// now, let us delete this key
	err = cstore.Delete(n1, p1)
	require.Nil(t, err, "%+v", err)
	_, err = cstore.Get(n1)
	require.NotNil(t, err)

	// let us re-create it from the mnemonic-phrase
	newInfo, err := cstore.Derive(n2,mnemonic, p2, 0, false, 0 )
	require.NoError(t, err)
	assert.Equal(t, n2, newInfo.Name)
	assert.Equal(t, info.Address(), newInfo.Address())
	assert.Equal(t, info.PubKey, newInfo.PubKey)
}

func ExampleNew() {
	// Select the encryption and storage for your cryptostore
	cstore := keys.New(
		dbm.NewMemDB(),
	)

	sec := keys.AlgoSecp256k1

	// Add keys and see they return in alphabetical order
	bob, _, err := cstore.CreateMnemonic("Bob", "english", "friend", sec)
	if err != nil {
		// this should never happen
		fmt.Println(err)
	} else {
		// return info here just like in List
		fmt.Println(bob.Name)
	}
	cstore.CreateMnemonic("Alice", "english", "secret", sec)
	cstore.CreateMnemonic("Carl", "english", "mitm", sec)
	info, _ := cstore.List()
	for _, i := range info {
		fmt.Println(i.Name)
	}

	// We need to use passphrase to generate a signature
	tx := []byte("deadbeef")
	sig, pub, err := cstore.Sign("Bob", "friend", tx)
	if err != nil {
		fmt.Println("don't accept real passphrase")
	}

	// and we can validate the signature with publicly available info
	binfo, _ := cstore.Get("Bob")
	if !binfo.PubKey.Equals(bob.PubKey) {
		fmt.Println("Get and CreateMnemonic return different keys")
	}

	if pub.Equals(binfo.PubKey) {
		fmt.Println("signed by Bob")
	}
	if !pub.VerifyBytes(tx, sig) {
		fmt.Println("invalid signature")
	}

	// Output:
	// Bob
	// Alice
	// Bob
	// Carl
	// signed by Bob
}
