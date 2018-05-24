package merkle

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type strHasher string

func (str strHasher) Hash() []byte {
	return SimpleHashFromBytes([]byte(str))
}

func TestSimpleMap(t *testing.T) {
	{
		db := newSimpleMap()
		db.Set("key1", strHasher("value1"))
		assert.Equal(t, "f544bcb4338dab8c5d5da4e8dfde617691da735c", fmt.Sprintf("%x", db.Hash()), "Hash didn't match")
	}
	{
		db := newSimpleMap()
		db.Set("key1", strHasher("value2"))
		assert.Equal(t, "8a275766d89cb1788357b197b0aad91f4caf09fb", fmt.Sprintf("%x", db.Hash()), "Hash didn't match")
	}
	{
		db := newSimpleMap()
		db.Set("key1", strHasher("value1"))
		db.Set("key2", strHasher("value2"))
		assert.Equal(t, "4a768df000f38b9d50d504b455c3a089b9c365fc", fmt.Sprintf("%x", db.Hash()), "Hash didn't match")
	}
	{
		db := newSimpleMap()
		db.Set("key2", strHasher("value2")) // NOTE: out of order
		db.Set("key1", strHasher("value1"))
		assert.Equal(t, "4a768df000f38b9d50d504b455c3a089b9c365fc", fmt.Sprintf("%x", db.Hash()), "Hash didn't match")
	}
	{
		db := newSimpleMap()
		db.Set("key1", strHasher("value1"))
		db.Set("key2", strHasher("value2"))
		db.Set("key3", strHasher("value3"))
		assert.Equal(t, "0681dc46eee71cf1e101bba27e865bcf27cfd85c", fmt.Sprintf("%x", db.Hash()), "Hash didn't match")
	}
	{
		db := newSimpleMap()
		db.Set("key2", strHasher("value2")) // NOTE: out of order
		db.Set("key1", strHasher("value1"))
		db.Set("key3", strHasher("value3"))
		assert.Equal(t, "0681dc46eee71cf1e101bba27e865bcf27cfd85c", fmt.Sprintf("%x", db.Hash()), "Hash didn't match")
	}
}
