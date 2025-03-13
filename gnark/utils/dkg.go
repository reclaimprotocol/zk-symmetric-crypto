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
	id, _ := strconv.Atoi(nodeID)
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
		x, _ := strconv.Atoi(nodeID)
		share := d.evaluatePolynomial(big.NewInt(int64(x)))
		d.Shares[nodeID] = share
	}
}

func (d *DKG) evaluatePolynomial(x *big.Int) *big.Int {
	result := new(big.Int).Set(d.Polynomial[d.Threshold-1]) // Start with highest degree term
	for i := d.Threshold - 2; i >= 0; i-- {                 // t-2 down to 0
		result.Mul(result, x)
		result.Add(result, d.Polynomial[i])
		result.Mod(result, &curve.Order)
	}
	return result
}

func (d *DKG) VerifyShares(commitments map[string][][]byte, nodeID string) error {
	x, _ := strconv.Atoi(nodeID)
	xBig := big.NewInt(int64(x))
	for fromNodeID, share := range d.ReceivedShares {
		commits := commitments[fromNodeID]
		var rhs twistededwards.PointAffine
		rhs.ScalarMultiplication(&curve.Base, share)
		var lhs twistededwards.PointAffine
		lhs.Set(&curve.Base)
		for i := 0; i < d.Threshold; i++ { // Changed from <= to <
			var term twistededwards.PointAffine
			err := term.Unmarshal(commits[i])
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
	ownShare := d.evaluatePolynomial(ownIndex)
	d.Secret.Add(d.Secret, ownShare)
	d.Secret.Mod(d.Secret, &curve.Order)

	// Compute public key from the final secret share
	d.PublicKey = new(twistededwards.PointAffine)
	d.PublicKey.ScalarMultiplication(&curve.Base, d.Secret)

	// Optional: Log for debugging
	fmt.Printf("Node %d: Included own share %s, final secret %s\n", d.ID, ownShare.String(), d.Secret.String())
}

func (d *DKG) ReconstructPrivateKey(secretShares map[int]*big.Int) *big.Int {
	result := new(big.Int)

	// Select first t shares
	selectedShares := make(map[int]*big.Int)
	count := 0
	for j, share := range secretShares {
		if count >= d.Threshold {
			break
		}
		selectedShares[j] = share
		count++
	}

	// Interpolate using only selected shares
	for j := range selectedShares {
		lambda := lagrangeCoefficient(j, selectedShares, big.NewInt(0), &curve.Order)
		term := new(big.Int).Mul(secretShares[j], lambda)
		term.Mod(term, &curve.Order)
		result.Add(result, term)
		result.Mod(result, &curve.Order)
	}
	return result
}

func (d *DKG) ReconstructMasterPublicKey(publicShares map[int][]byte) *twistededwards.PointAffine {
	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()
	points := make(map[int]*twistededwards.PointAffine)
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
		used++
	}
	for j := range points {
		lambda := lagrangeCoefficient(j, points, big.NewInt(0), &curve.Order)
		term := new(twistededwards.PointAffine).ScalarMultiplication(points[j], lambda)
		result.Add(result, term)
	}
	return result
}

func lagrangeCoefficient(j int, points interface{}, x, modulus *big.Int) *big.Int {
	num := big.NewInt(1)
	den := big.NewInt(1)
	switch p := points.(type) {
	case map[int]*big.Int:
		for i := range p {
			if i != j {
				num.Mul(num, new(big.Int).Sub(x, big.NewInt(int64(i))))
				den.Mul(den, new(big.Int).Sub(big.NewInt(int64(j)), big.NewInt(int64(i))))
			}
		}
	case map[int]*twistededwards.PointAffine:
		for i := range p {
			if i != j {
				num.Mul(num, new(big.Int).Sub(x, big.NewInt(int64(i))))
				den.Mul(den, new(big.Int).Sub(big.NewInt(int64(j)), big.NewInt(int64(i))))
			}
		}
	}
	if num.Sign() < 0 {
		num.Add(num, modulus)
	}
	if den.Sign() < 0 {
		den.Add(den, modulus)
	}
	denInv := new(big.Int).ModInverse(den, modulus)
	return new(big.Int).Mod(new(big.Int).Mul(num, denInv), modulus)
}

func (d *DKG) MarshalCommitments() ([]byte, error) {
	commitments := make([][]byte, len(d.PublicCommits)) // Length is d.Threshold
	for i, commit := range d.PublicCommits {
		commitments[i] = commit.Marshal()
	}
	return json.Marshal(&commitments)
}
