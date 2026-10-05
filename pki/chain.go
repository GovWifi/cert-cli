package pki

import (
	"fmt"
	"time"
)

// Chain is a root CA, an intermediate CA signed by that root, and end-entity
// certificates signed by the intermediate.
type Chain struct {
	Root         *CADetails
	Intermediate *CADetails
	Leaves       []*CADetails
}

// CreateChain generates a root CA, an intermediate CA signed by that root, and
// leafCount end-entity certificates signed by the intermediate. The root is
// valid until RootExpiry, the intermediate until IntermediateExpiry, and each
// leaf until LeafExpiry. notBefore is the start of every certificate.
func CreateChain(leafCount int, notBefore time.Time) (*Chain, error) {
	if err := validateLeafCount(leafCount); err != nil {
		return nil, err
	}

	root, err := CreateRootCA(notBefore, RootExpiry)
	if err != nil {
		return nil, err
	}

	intermediate, err := CreateIntermediateCA(root.Cert, root.Key, notBefore, IntermediateExpiry)
	if err != nil {
		return nil, err
	}

	leaves := make([]*CADetails, 0, leafCount)
	for i := 1; i <= leafCount; i++ {
		leaf, err := CreateLeaf(intermediate.Cert, intermediate.Key, LeafCommonName(i), notBefore, LeafExpiry)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}

	return &Chain{
		Root:         root,
		Intermediate: intermediate,
		Leaves:       leaves,
	}, nil
}

func validateLeafCount(leafCount int) error {
	if leafCount < 1 {
		return fmt.Errorf("leaves must be at least 1")
	}
	if leafCount > MaxLeafCount {
		return fmt.Errorf("leaves must be at most %d", MaxLeafCount)
	}
	return nil
}
