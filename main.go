package merkle_signing

import (
	"crypto"
	"crypto/sha512"
	"github.com/cbergoon/merkletree"
	"github.com/oasisprotocol/ed25519"
)

type MerkleSig struct {
	Pub     ed25519.PublicKey
	RootSig []byte
	Path    [][]byte
	Indexes []bool
}

func SignMerkle(priv *ed25519.PrivateKey, pub ed25519.PublicKey, items []merkletree.Content) []MerkleSig {
	t, err := merkletree.NewTreeWithHashStrategy(items, sha512.New)
	if err != nil {
		panic(err)
	}
	root := t.MerkleRoot()
	opts := ed25519.Options{
		Hash: crypto.SHA512,
	}

	rootSig, err := priv.Sign(nil, root, &opts)
	if err != nil {
		panic(err)
	}

	sigs := make([]MerkleSig, len(items))
	for i, item := range items {
		path, indexesInt64, err := t.GetMerklePath(item)
		if err != nil {
			panic(err)
		}
		indexes := make([]bool, len(indexesInt64))
		for j, index := range indexesInt64 {
			indexes[j] = index == 1
		}

		sigs[i] = MerkleSig{
			Pub:     pub,
			RootSig: rootSig,
			Path:    path,
			Indexes: indexes,
		}
	}

	return sigs
}

func VerifyMerkle(hash []byte, sig MerkleSig) (bool, error) {
	// calculate master
	current := hash
	for i := range sig.Path {
		h := sha512.New()
		hash := sig.Path[i]
		index := sig.Indexes[i]
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

	// `current` should now be the merkle root.

	opts := ed25519.Options{
		Hash: crypto.SHA512,
	}

	valid := ed25519.VerifyWithOptions(sig.Pub, current, sig.RootSig, &opts)
	return valid, nil
}
