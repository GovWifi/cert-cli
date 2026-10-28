package pki

import (
	"fmt"
	"strings"
	"time"
)

// Chain is a root CA, an intermediate CA signed by that root, and end-entity
// certificates signed by the intermediate.
type Chain struct {
	Root         *CADetails
	Intermediate *CADetails
	Leaves       []*CADetails
}

// ChainOptions configures CreateCustomChain. Empty organization and common names
// fall back to the GovWifi defaults. Empty time fields are not allowed; callers
// must set each validity window.
type ChainOptions struct {
	Organization     string
	RootCN           string
	IntermediateCN   string
	LeafCount        int
	RootNotBefore    time.Time
	RootNotAfter     time.Time
	InterNotBefore   time.Time
	InterNotAfter    time.Time
	LeafNotBefore    time.Time
	LeafNotAfter     time.Time
}

// CreateChain generates a root CA, an intermediate CA signed by that root, and
// leafCount end-entity certificates signed by the intermediate. The root is
// valid until RootExpiry, the intermediate until IntermediateExpiry, and each
// leaf until LeafExpiry. notBefore is the start of every certificate.
func CreateChain(leafCount int, notBefore time.Time) (*Chain, error) {
	return CreateCustomChain(ChainOptions{
		LeafCount:      leafCount,
		RootNotBefore:  notBefore,
		RootNotAfter:   RootExpiry,
		InterNotBefore: notBefore,
		InterNotAfter:  IntermediateExpiry,
		LeafNotBefore:  notBefore,
		LeafNotAfter:   LeafExpiry,
	})
}

// CreateCustomChain generates a root CA, an intermediate CA signed by that root,
// and leaf certificates signed by the intermediate using the given subject and
// validity options.
func CreateCustomChain(opts ChainOptions) (*Chain, error) {
	if err := validateLeafCount(opts.LeafCount); err != nil {
		return nil, err
	}

	organization := strings.TrimSpace(opts.Organization)
	if organization == "" {
		organization = govWifiOrganization
	}
	rootCN := strings.TrimSpace(opts.RootCN)
	if rootCN == "" {
		rootCN = RootCN
	}
	interCN := strings.TrimSpace(opts.IntermediateCN)
	if interCN == "" {
		interCN = IntermediateCN
	}

	root, err := CreateRootCAWithSubject(organization, rootCN, opts.RootNotBefore, opts.RootNotAfter)
	if err != nil {
		return nil, err
	}

	intermediate, err := CreateIntermediateCAWithSubject(root.Cert, root.Key, organization, interCN, opts.InterNotBefore, opts.InterNotAfter)
	if err != nil {
		return nil, err
	}

	leaves := make([]*CADetails, 0, opts.LeafCount)
	for i := 1; i <= opts.LeafCount; i++ {
		leaf, err := CreateLeafWithSubject(intermediate.Cert, intermediate.Key, organization, LeafCommonName(i), opts.LeafNotBefore, opts.LeafNotAfter)
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
