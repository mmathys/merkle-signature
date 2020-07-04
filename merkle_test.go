package merkle_signing

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/oasisprotocol/ed25519"
	"strconv"
	"testing"
)

type UTXO struct {
	x string
}

//CalculateHash hashes the fields of an UTXO
func (t UTXO) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func TestInterface(t *testing.T) {
	var hashes [][]byte
	for i := 1; i <= 5; i++ {
		hash, err := UTXO{x: strconv.Itoa(i)}.CalculateHash()
		if err != nil {
			panic(err)
		}
		hashes = append(hashes, hash)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	sigs := SignMerkle(&priv, pub, hashes)

	for i, sig := range sigs {
		valid, err := VerifyMerkle(hashes[i], sig)
		if err != nil {
			panic(err)
		}

		if !valid {
			t.Fatal("verification was not valid")
		}

		hashes[i][0] = byte(1)
		invalid, err := VerifyMerkle(hashes[i], sig)
		if err != nil {
			panic(err)
		}

		if invalid {
			t.Fatal("wanted invalid verification, but got valid")
		}
	}

}

func TestSingle(t *testing.T) {
	hash, err := UTXO{x: "1"}.CalculateHash()
	if err != nil {
		panic(err)
	}

	items := [][]byte{hash}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sigs := SignMerkle(&priv, pub, items)
	if len(sigs) != 1 {
		t.Fatal("wrong length")
	}

	valid, err := VerifyMerkle(hash, sigs[0])
	if err != nil {
		panic(err)
	}

	if !valid {
		t.Fatal("verification was not valid")
	}
}
