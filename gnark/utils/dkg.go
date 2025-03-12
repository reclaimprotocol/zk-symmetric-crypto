package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

var curve = twistededwards.GetEdwardsCurve()

type DKG struct {
	Threshold      int
	NumNodes       int
	Nodes          []string
	Secret         *big.Int
	Polynomial     []*big.Int
	PublicCommits  []*twistededwards.PointAffine
	Shares         map[string]*big.Int
	ReceivedShares map[string]*big.Int
	SecretShare    *big.Int
	PublicKey      *twistededwards.PointAffine
}

func NewDKG(threshold, numNodes int, nodes []string) *DKG {
	return &DKG{
		Threshold:      threshold,
		NumNodes:       numNodes,
		Nodes:          nodes,
		Shares:         make(map[string]*big.Int),
		ReceivedShares: make(map[string]*big.Int),
	}
}

func (d *DKG) GeneratePolynomials() {
	d.Secret, _ = rand.Int(rand.Reader, &curve.Order)
	d.Polynomial = make([]*big.Int, d.Threshold)
	d.Polynomial[0] = new(big.Int).Set(d.Secret)
	for i := 1; i < d.Threshold; i++ {
		d.Polynomial[i], _ = rand.Int(rand.Reader, &curve.Order)
	}
	d.PublicCommits = make([]*twistededwards.PointAffine, d.Threshold)
	for i := 0; i < d.Threshold; i++ {
		d.PublicCommits[i] = new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, d.Polynomial[i])
	}
}

func (d *DKG) GenerateShares() {
	for _, nodeID := range d.Nodes {
		idNum, _ := big.NewInt(0).SetString(nodeID[4:], 10)
		d.Shares[nodeID] = evaluatePolynomial(d.Polynomial, idNum, &curve.Order)
	}
}

func (d *DKG) VerifyShares(commitments map[string][]*twistededwards.PointAffine, nodeID string) error {
	for senderID, share := range d.ReceivedShares {
		senderCommits := commitments[senderID]
		lhs := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, share)
		rhs := new(twistededwards.PointAffine)
		rhs.X.SetZero()
		rhs.Y.SetOne()
		x, _ := big.NewInt(0).SetString(nodeID[4:], 10)
		for i := 0; i < d.Threshold; i++ {
			xPow := new(big.Int).Exp(x, big.NewInt(int64(i)), &curve.Order)
			term := new(twistededwards.PointAffine).ScalarMultiplication(senderCommits[i], xPow)
			rhs.Add(rhs, term)
		}
		if !lhs.Equal(rhs) {
			return fmt.Errorf("share verification failed for %s from %s", nodeID, senderID)
		}
	}
	return nil
}

func (d *DKG) ComputeFinalKeys() {
	secretShare := big.NewInt(0)
	for _, share := range d.ReceivedShares {
		secretShare.Add(secretShare, share)
	}
	secretShare.Mod(secretShare, &curve.Order)
	d.SecretShare = secretShare
	d.PublicKey = new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, secretShare)
}

func (d *DKG) ReconstructMasterPublicKey(publicShares map[string]*twistededwards.PointAffine) *twistededwards.PointAffine {
	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()
	points := make(map[int]*twistededwards.PointAffine)
	used := 0
	for nodeID, pubKey := range publicShares {
		if used >= d.Threshold {
			break
		}
		idNum, _ := big.NewInt(0).SetString(nodeID[4:], 10)
		points[int(idNum.Int64())] = pubKey
		used++
	}
	for j := range points {
		lambda := lagrangeCoefficient(j, points, big.NewInt(0), &curve.Order)
		term := new(twistededwards.PointAffine).ScalarMultiplication(points[j], lambda)
		result.Add(result, term)
	}
	return result
}

func evaluatePolynomial(coeffs []*big.Int, x, modulus *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coeffs[i])
		result.Mod(result, modulus)
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
