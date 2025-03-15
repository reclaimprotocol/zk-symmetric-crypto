package utils

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type DKG struct {
	Threshold      int
	NumNodes       int
	Nodes          []string // ["1", "2", ...]
	ID             int      // Numeric ID: 1, 2, ...
	Polynomial     []*big.Int
	PublicCommits  []*twistededwards.PointAffine
	Shares         map[string]*big.Int // Keyed by string ID
	ReceivedShares map[string]*big.Int // Keyed by string ID
	PublicKey      *twistededwards.PointAffine
	Secret         *big.Int
}

var curve = twistededwards.GetEdwardsCurve()

func NewDKG(threshold, numNodes int, nodes []string, nodeID string) *DKG {
	id, err := strconv.Atoi(nodeID)
	if err != nil {
		panic(err)
	}
	return &DKG{
		Threshold:      threshold,
		NumNodes:       numNodes,
		Nodes:          nodes,
		ID:             id,
		Shares:         make(map[string]*big.Int),
		ReceivedShares: make(map[string]*big.Int),
	}
}

func (d *DKG) GeneratePolynomials() {
	d.Polynomial = make([]*big.Int, d.Threshold) // Degree t-1, t coefficients
	d.PublicCommits = make([]*twistededwards.PointAffine, d.Threshold)
	for i := 0; i < d.Threshold; i++ { // 0 to t-1
		coef, _ := rand.Int(rand.Reader, &curve.Order)
		d.Polynomial[i] = coef
		var commit twistededwards.PointAffine
		commit.ScalarMultiplication(&curve.Base, coef)
		d.PublicCommits[i] = &commit
	}
}

func (d *DKG) GenerateShares() {
	for _, nodeID := range d.Nodes {
		if nodeID == fmt.Sprintf("%d", d.ID) {
			continue
		}
		x, err := strconv.Atoi(nodeID)
		if err != nil {
			panic(err)
		}
		share := EvaluatePolynomial(d.Polynomial, big.NewInt(int64(x)))
		d.Shares[nodeID] = share
	}
}

func EvaluatePolynomial(polynomial []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(polynomial[len(polynomial)-1])
	for i := len(polynomial) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, polynomial[i])
		result.Mod(result, &curve.Order)
	}
	return result
}

func (d *DKG) VerifyShares(commitments map[string][][]byte, nodeID string) error {
	x, err := strconv.Atoi(nodeID)
	if err != nil {
		panic(err)
	}
	xBig := big.NewInt(int64(x))
	for fromNodeID, share := range d.ReceivedShares {
		commits := commitments[fromNodeID]
		var rhs twistededwards.PointAffine
		rhs.ScalarMultiplication(&curve.Base, share)
		var lhs twistededwards.PointAffine
		lhs.Set(&curve.Base)
		for i := 0; i < d.Threshold; i++ { // Changed from <= to <
			var term twistededwards.PointAffine
			err = term.Unmarshal(commits[i])
			if err != nil {
				return err
			}
			for j := 0; j < i; j++ {
				term.ScalarMultiplication(&term, xBig)
			}
			if i == 0 {
				lhs.Set(&term)
			} else {
				lhs.Add(&lhs, &term)
			}
		}
		if !lhs.Equal(&rhs) {
			return fmt.Errorf("share from %s does not verify for %d", fromNodeID, x)
		}
		fmt.Printf("%d: Verified share from %s\n", x, fromNodeID)
	}
	return nil
}

func (d *DKG) ComputeFinalKeys() {
	d.Secret = new(big.Int)

	// Add received shares from other nodes
	for _, share := range d.ReceivedShares {
		d.Secret.Add(d.Secret, share)
		d.Secret.Mod(d.Secret, &curve.Order)
	}

	// Add own share: evaluate own polynomial at own index
	ownIndex := big.NewInt(int64(d.ID))
	ownShare := EvaluatePolynomial(d.Polynomial, ownIndex)
	d.Secret.Add(d.Secret, ownShare)
	d.Secret.Mod(d.Secret, &curve.Order)

	// Compute public key from the final secret share
	d.PublicKey = new(twistededwards.PointAffine)
	d.PublicKey.ScalarMultiplication(&curve.Base, d.Secret)

	// Optional: Log for debugging
	// fmt.Printf("Node %d: Included own share %s, final secret %s\n", d.ID, ownShare.String(), d.Secret.String())
}

func (d *DKG) ReconstructMasterPublicKey(publicShares map[int][]byte) *twistededwards.PointAffine {
	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()
	points := make(map[int]*twistededwards.PointAffine)
	var indices []int
	used := 0
	var ids []int
	for nodeID := range publicShares {
		ids = append(ids, nodeID)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if used >= d.Threshold {
			break
		}
		pubShare := &twistededwards.PointAffine{}
		err := pubShare.Unmarshal(publicShares[id])
		if err != nil {
			return nil
		}
		points[id] = pubShare
		indices = append(indices, id)
		used++
	}
	for j := range points {
		lambda, _ := LagrangeCoefficient(j, indices)
		term := new(twistededwards.PointAffine).ScalarMultiplication(points[j], lambda)
		result.Add(result, term)
	}
	return result
}

func (d *DKG) ReconstructPrivateKey(secretShares map[int]*big.Int) *big.Int {
	result := new(big.Int)
	var indices []int
	count := 0
	for j := range secretShares {
		if count >= d.Threshold {
			break
		}
		indices = append(indices, j)
		count++
	}
	for _, j := range indices {
		lambda, _ := LagrangeCoefficient(j, indices)
		term := new(big.Int).Mul(secretShares[j], lambda)
		term.Mod(term, &curve.Order)
		result.Add(result, term)
		result.Mod(result, &curve.Order)
	}
	return result
}

// LagrangeCoefficient computes the Lagrange coefficient λ_shareID(x) for a given shareID
// and a set of indices, used in polynomial interpolation. The result is computed modulo
// the curve order (curve.Order). This function is critical for DKG and must handle all
// edge cases to prevent subtle bugs.
func LagrangeCoefficient(shareID int, indices []int) (*big.Int, error) {
	// Step 1: Validate inputs
	if len(indices) == 0 {
		return nil, fmt.Errorf("indices cannot be empty")
	}
	// Check for duplicates in indices, as they would lead to a zero denominator
	seen := make(map[int]bool)
	for _, idx := range indices {
		if idx == 0 {
			panic("indices cannot be zero")
		}
		if seen[idx] {
			return nil, fmt.Errorf("duplicate index %d in indices", idx)
		}
		seen[idx] = true
	}
	// Validate that shareID is in indices (required for correct interpolation in DKG)
	if !seen[shareID] {
		return nil, fmt.Errorf("shareID %d not found in indices; must be one of the interpolation points", shareID)
	}

	modulus := &curve.Order
	if modulus.Sign() <= 0 {
		return nil, fmt.Errorf("curve order is invalid (non-positive)")
	}

	// Step 2: Initialize numerator and denominator
	num := big.NewInt(1) // Product of (x - x_j) for j != shareID
	den := big.NewInt(1) // Product of (shareID - x_j) for j != shareID
	x := big.NewInt(0)   // In DKG, we evaluate at x = 0 (secret reconstruction)

	// Step 3: Compute the Lagrange terms
	for _, idx := range indices {
		if idx == shareID {
			continue // Skip the shareID term to avoid zero in denominator
		}
		idxBig := big.NewInt(int64(idx))
		shareIDBig := big.NewInt(int64(shareID))

		// Numerator: (x - idx)
		numTerm := new(big.Int).Sub(x, idxBig)
		num.Mul(num, numTerm)
		num.Mod(num, modulus) // Keep intermediate results bounded

		// Denominator: (shareID - idx)
		denTerm := new(big.Int).Sub(shareIDBig, idxBig)
		if denTerm.Sign() == 0 {
			return nil, fmt.Errorf("denominator term (shareID %d - idx %d) is zero", shareID, idx)
		}
		den.Mul(den, denTerm)
		den.Mod(den, modulus) // Keep intermediate results bounded
	}

	// Step 4: Compute the modular inverse of the denominator
	den.Mod(den, modulus) // Ensure denominator is in the field
	denInv := new(big.Int).ModInverse(den, modulus)
	if denInv == nil {
		return nil, fmt.Errorf("failed to compute modular inverse of denominator %s modulo %s", den.String(), modulus.String())
	}

	// Step 5: Compute the final coefficient: num * denInv mod modulus
	result := new(big.Int).Mul(num, denInv)
	result.Mod(result, modulus)

	// Step 6: Sanity check (optional, can be removed in production)
	if result.Sign() < 0 || result.Cmp(modulus) >= 0 {
		return nil, fmt.Errorf("result %s is out of bounds [0, %s)", result.String(), modulus.String())
	}

	return result, nil
}

func (d *DKG) MarshalCommitments() ([]byte, error) {
	commitments := make([][]byte, len(d.PublicCommits)) // Length is d.Threshold
	for i, commit := range d.PublicCommits {
		commitments[i] = commit.Marshal()
	}
	return json.Marshal(&commitments)
}
