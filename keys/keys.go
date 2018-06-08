package keys

type CryptoAlgo string

const (
	AlgoEd25519   = CryptoAlgo("ed25519")
	AlgoSecp256k1 = CryptoAlgo("secp256k1")
)