package utils

import (
	"crypto/rand"
	"math"
	"math/big"
	rnd "math/rand/v2"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type Share struct {
	Index      int
	PrivateKey *big.Int
	PublicKey  *twistededwards.PointAffine
}

func TOPRFCreateShares(n, threshold int, secret *big.Int) ([]*Share, error) {
	curve := twistededwards.GetEdwardsCurve()
	gf := &GF{P: TNBCurveOrder}
	a := make([]*big.Int, threshold-1)
	for i := 0; i < threshold-1; i++ {
		r, err := rand.Int(rand.Reader, TNBCurveOrder)
		if err != nil {
			return nil, err
		}
		a[i] = r
	}

	shares := make([]*Share, n)
	// f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ⋯ + a_(k−1)*x^(k−1)
	for i := 0; i < n; i++ {
		shareIndex := i + 1
		x := big.NewInt(int64(shareIndex))
		shares[i] = &Share{
			Index: shareIndex,
		}

		shares[i].PrivateKey = new(big.Int).Set(secret)
		for j := 0; j < threshold-1; j++ {
			tmp := gf.Mul(a[j], x)
			for exp := 0; exp < j; exp++ {
				tmp = gf.Mul(tmp, x)
			}
			shares[i].PrivateKey = gf.Add(tmp, shares[i].PrivateKey)
		}

		shares[i].PublicKey = &twistededwards.PointAffine{}
		shares[i].PublicKey.ScalarMultiplication(&curve.Base, shares[i].PrivateKey)
	}

	return shares, nil
}

// Coeff calculates Lagrange coefficient for node with index idx
func Coeff(idx int, peers []int) *big.Int {

	// All peer indexes are [idx] + 1

	gf := &GF{P: TNBCurveOrder}
	peerLen := len(peers)
	iScalar := big.NewInt(int64(idx + 1))
	divident := big.NewInt(1)
	divisor := big.NewInt(1)

	for i := 0; i < peerLen; i++ {
		if peers[i] == idx {
			continue
		}
		tmp := big.NewInt(int64(peers[i] + 1))
		divident = gf.Mul(divident, tmp)
		tmp = gf.Sub(tmp, iScalar)
		divisor = gf.Mul(divisor, tmp)
	}
	divisor = gf.Inv(divisor)
	return gf.Mul(divisor, divident)
}

func TOPRFThresholdMul(idxs []int, elements []*twistededwards.PointAffine) *twistededwards.PointAffine {
	result := &twistededwards.PointAffine{}
	result.X.SetZero()
	result.Y.SetOne()

	for i := 0; i < len(elements); i++ {
		lPoly := Coeff(idxs[i], idxs)
		gki := &twistededwards.PointAffine{}
		gki.ScalarMultiplication(elements[i], lPoly)
		result.Add(result, gki)
	}
	return result
}

func TOPRFFinalize(idxs []int, elements []*twistededwards.PointAffine, secretElements [2]*big.Int, mask *big.Int) (*big.Int, error) {

	res := TOPRFThresholdMul(idxs, elements)

	// output calc
	invR := new(big.Int)
	invR.ModInverse(mask, TNBCurveOrder) // mask^-1

	deblinded := &twistededwards.PointAffine{}
	deblinded.ScalarMultiplication(res, invR) // H *mask * sk * mask^-1 = H * sk

	x := deblinded.X.BigInt(new(big.Int))
	y := deblinded.Y.BigInt(new(big.Int))

	out := hashToScalar(x.Bytes(), y.Bytes(), secretElements[0].Bytes(), secretElements[1].Bytes())

	return new(big.Int).SetBytes(out), nil
}

type SharedKey struct {
	PrivateKey *big.Int
	PublicKey  *twistededwards.PointAffine
	Shares     []*Share
}

func TOPRFGenerateSharedKey(nodes, threshold int) *SharedKey {

	curve := twistededwards.GetEdwardsCurve()
	sk, _ := rand.Int(rand.Reader, TNBCurveOrder)
	serverPublic := &twistededwards.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	if threshold >= nodes {
		panic("threshold must be smaller than nodes")
	}

	shares, err := TOPRFCreateShares(nodes, threshold, sk)
	if err != nil {
		panic(err)
	}
	shareParams := make([]*Share, len(shares))
	for i, share := range shares {
		shareParams[i] = &Share{
			Index:      i,
			PrivateKey: share.PrivateKey,
			PublicKey:  share.PublicKey,
		}
	}

	return &SharedKey{
		PrivateKey: sk,
		PublicKey:  serverPublic,
		Shares:     shareParams,
	}
}

type Src struct{}

func (Src) Uint64() uint64 {
	i, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(math.MaxUint64))
	return i.Uint64()
}

func PickRandomIndexes(n, k int) []int {
	r := rnd.New(Src{})
	idxs := r.Perm(n)
	return idxs[:k]
}
