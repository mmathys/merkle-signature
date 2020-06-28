package merkle_signing

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/cbergoon/merkletree"
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

// path verification algorithmus
func VerifyPath(target []byte, path [][]byte, indexes []int64, master []byte) (bool, error) {
	// calculate master
	current := target
	for i := range path {
		h := sha256.New()
		hash := path[i]
		index := indexes[i]
		var msg []byte
		if index == 0 {
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
	t, err := merkletree.NewTree(list)
	if err != nil {
		panic(err)
	}

	fmt.Printf("merkle root: %v\n", t.MerkleRoot())

	path, indexes, err := t.GetMerklePath(UTXO{x: "2"})
	hash, _ := UTXO{x: "2"}.CalculateHash()
	validPath, err := VerifyPath(hash, path, indexes, t.MerkleRoot())
	if err != nil {
		panic(err)
	}

	/*
	The signature of the merkle signing UTXO is defined as follows:
	- merkle root
	- signature of the merkle root
	- path from own hash to merkle root
		- `path`: the hash path from our own hash to merkle root (own hash and merkle root are not included)
		- `indexes`: 0 if the defined hash is a left leaf, 1 if right
		(idea: indexes can be left out if we fix the order of the leaves (lexicographic), but later)
	*/

	fmt.Printf("path verification: %t\n", validPath)

}
