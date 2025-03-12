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
	d.Polynomial = make([]*big.Int, d.Threshold+1)
	d.PublicCommits = make([]*twistededwards.PointAffine, d.Threshold+1)
	for i := 0; i <= d.Threshold; i++ {
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
	result := new(big.Int).Set(d.Polynomial[d.Threshold])
	for i := d.Threshold - 1; i >= 0; i-- {
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
		for i := 0; i <= d.Threshold; i++ {
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
	for _, share := range d.ReceivedShares {
		// fmt.Printf("%d: Adding share from %s: %s\n", d.ID, fromNodeID, share.String())
		d.Secret.Add(d.Secret, share)
		d.Secret.Mod(d.Secret, &curve.Order)
	}
	// fmt.Printf("%d: Final secret: %s\n", d.ID, d.Secret.String())
	d.PublicKey = new(twistededwards.PointAffine)
	d.PublicKey.ScalarMultiplication(&curve.Base, d.Secret)
}

func (d *DKG) ReconstructMasterPublicKey(publicShares map[string][]byte) *twistededwards.PointAffine {
	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()
	points := make(map[int]*twistededwards.PointAffine)
	used := 0
	// Use first Threshold numeric IDs
	var ids []int
	for nodeID := range publicShares {
		id, err := strconv.Atoi(nodeID)
		if err != nil {
			panic(err)
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if used >= d.Threshold {
			break
		}
		nodeID := fmt.Sprintf("%d", id)
		pubShare := &twistededwards.PointAffine{}
		err := pubShare.Unmarshal(publicShares[nodeID])
		if err != nil {
			return nil
		}
		points[id] = pubShare
		// fmt.Printf("%d: Using public share %d: X=%s, Y=%s\n", d.ID, id, publicShares[nodeID].X.String(), publicShares[nodeID].Y.String())
		used++
	}
	for j := range points {
		lambda := lagrangeCoefficient(j, points, big.NewInt(0), &curve.Order)
		// fmt.Printf("%d: Lagrange coefficient for %d: %s\n", d.ID, j, lambda.String())
		term := new(twistededwards.PointAffine).ScalarMultiplication(points[j], lambda)
		result.Add(result, term)
	}
	return result
}

func lagrangeCoefficient(j int, points map[int]*twistededwards.PointAffine, x, modulus *big.Int) *big.Int {
	num := big.NewInt(1)
	den := big.NewInt(1)
	for i := range points {
		if i != j {
			num.Mul(num, new(big.Int).Sub(x, big.NewInt(int64(i))))
			den.Mul(den, new(big.Int).Sub(big.NewInt(int64(j)), big.NewInt(int64(i))))
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
	commitments := make([][]byte, len(d.PublicCommits))
	for i, commit := range d.PublicCommits {
		commitments[i] = commit.Marshal()
	}
	return json.Marshal(&commitments)
}
