package merkle_signing

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/cbergoon/merkletree"
	"github.com/oasisprotocol/ed25519"
	"log"
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

// This function is for testing only.
func verifyPath(target []byte, path [][]byte, indexes []bool, master []byte) (bool, error) {
	// calculate master
	current := target
	for i := range path {
		h := sha512.New()
		hash := path[i]
		index := indexes[i]
		var msg []byte
		if index == false {
			// hash is left
			msg = append(hash, current...)
		} else {
			// hash is right
			msg = append(current, hash...)
		}
		if _, err := h.Write(msg); err != nil {
			return false, err
		}

		current = h.Sum(nil)
	}

	return bytes.Equal(master, current), nil
}

func TestBasic(test *testing.T) {
	//Build list of Content to build tree
	var list []merkletree.Content
	list = append(list, UTXO{x: "1"})
	list = append(list, UTXO{x: "2"})
	list = append(list, UTXO{x: "3"})
	list = append(list, UTXO{x: "4"})
	list = append(list, UTXO{x: "5"})

	// Create a new Merkle Tree
	t, err := merkletree.NewTreeWithHashStrategy(list, sha512.New)
	if err != nil {
		panic(err)
	}

	fmt.Printf("merkle root: %v\n", t.MerkleRoot())

	path, indexesInt64, err := t.GetMerklePath(UTXO{x: "2"})
	hash, _ := UTXO{x: "2"}.CalculateHash()
	indexes := make([]bool, len(indexesInt64))
	for i, index := range indexesInt64 {
		indexes[i] = index == 1
	}
	validPath, err := verifyPath(hash, path, indexes, t.MerkleRoot())
	if err != nil {
		panic(err)
	}
	if !validPath {
		log.Fatalf("had valid path, but validPath was false")
	}

	path[0][0] = byte(0)
	invalidPath, err := verifyPath(hash, path, indexes, t.MerkleRoot())
	if err != nil {
		panic(err)
	}

	if invalidPath {
		log.Fatalf("had invalid path, but invalidPath was true")
	}
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
