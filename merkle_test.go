package merkle_signing

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/cbergoon/merkletree"
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

// exported equals fn
func (t UTXO) Equals(other merkletree.Content) (bool, error) {
	return t.x == other.(UTXO).x, nil
}

func TestInterface(t *testing.T) {
	var items []merkletree.Content
	for i := 1; i <= 5; i++ {
		utxo := UTXO{x: strconv.Itoa(i)}
		items = append(items, utxo)
	}


	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	sigs := SignMerkle(&priv, pub, items)

	for i, sig := range sigs {
		hash, err := items[i].CalculateHash()
		if err != nil {
			panic(err)
		}

		valid, err := VerifyMerkle(hash, sig)
		if err != nil {
			panic(err)
		}

		if !valid {
			t.Fatal("verification was not valid")
		}
	}

}
