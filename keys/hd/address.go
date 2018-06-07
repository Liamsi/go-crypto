package hd

// XXX This package doesn't work with our address scheme,
// XXX and it probably doesn't work for our other pubkey types.
// XXX Fix it up to be more general but compatible.

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/go-crypto"
)

// ComputeMastersFromSeed returns the master public key, master secret, and chain code in hex.
func ComputeMastersFromSeed(seed []byte) (secret [32]byte, chainCode [32]byte) {
	masterSecret := []byte("Bitcoin seed")
	secret, chainCode = i64(masterSecret, seed)

	return
}

//-------------------------------------------------------------------

// DerivePrivateKeyForPath derives the private key by following the path from privKeyBytes,
// using the given chainCode.
func DerivePrivateKeyForPath(privKeyBytes [32]byte, chainCode [32]byte, path string) [32]byte {
	data := privKeyBytes
	parts := strings.Split(path, "/")
	for _, part := range parts {
		prime := part[len(part)-1:] == "'"
		// prime == private derivation. Otherwise public.
		if prime {
			part = part[:len(part)-1]
		}
		i, err := strconv.Atoi(part)
		if err != nil {
			panic(err)
		}
		if i < 0 {
			panic(errors.New("index too large"))
		}
		data, chainCode = DerivePrivateKey(data, chainCode, uint32(i), prime)
		//printKeyInfo(data, nil, chain)
	}
	var derivedKey [32]byte
	n := copy(derivedKey[:], data[:])
	if n != 32 || len(data) != 32 {
		panic(fmt.Sprintf("expected a key of length 32, got: %v", len(data)))
	}
	return derivedKey
}


// DerivePrivateKey derives the private key with index and chainCode.
// If prime is true, the derivation is 'hardened'.
// It returns the new private key and new chain code.
func DerivePrivateKey(privKeyBytes [32]byte, chainCode [32]byte, index uint32, prime bool) ([32]byte, [32]byte) {
	var data []byte
	if prime {
		index = index | 0x80000000
		data = append([]byte{byte(0)}, privKeyBytes[:]...)
	} else {
		public := crypto.PrivKeySecp256k1(privKeyBytes).PubKey().(crypto.PubKeySecp256k1)
		data = public[:]
	}
	data = append(data, uint32ToBytes(index)...)
	data2, chainCode2 := i64(chainCode[:], data)
	x := addScalars(privKeyBytes[:], data2[:])
	return x, chainCode2
}



// modular big endian addition
func addScalars(a []byte, b []byte) [32]byte {
	aInt := new(big.Int).SetBytes(a)
	bInt := new(big.Int).SetBytes(b)
	sInt := new(big.Int).Add(aInt, bInt)
	x := sInt.Mod(sInt, btcec.S256().N).Bytes()
	x2 := [32]byte{}
	copy(x2[32-len(x):], x)
	return x2
}

func uint32ToBytes(i uint32) []byte {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], i)
	return b[:]
}

//-------------------------------------------------------------------

// i64 returns the two halfs of the SHA512 HMAC of key and data.
func i64(key []byte, data []byte) (IL [32]byte, IR [32]byte) {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	I := mac.Sum(nil)
	copy(IL[:], I[:32])
	copy(IR[:], I[32:])
	return
}