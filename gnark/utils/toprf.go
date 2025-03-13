package utils

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	rnd "math/rand/v2"
	"strconv"

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

func reconstructPrivateKey(shares []*Share, T int) *big.Int {
	if len(shares) < T {
		return nil
	}
	indices := make([]int, T)
	for i, share := range shares[:T] {
		indices[i] = share.Index
	}
	result := new(big.Int)
	for _, share := range shares[:T] {
		lambda, _ := LagrangeCoefficient(share.Index, indices)
		term := new(big.Int).Mul(share.PrivateKey, lambda)
		term.Mod(term, &curve.Order)
		result.Add(result, term)
		result.Mod(result, &curve.Order)
	}
	return result
}

func reconstructPublicKey(shares []*Share, T int) *twistededwards.PointAffine {
	if len(shares) < T {
		return nil
	}
	indices := make([]int, T)
	for i, share := range shares[:T] {
		indices[i] = share.Index
	}
	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()
	for _, share := range shares[:T] {
		lambda, _ := LagrangeCoefficient(share.Index, indices)
		term := new(twistededwards.PointAffine).ScalarMultiplication(share.PublicKey, lambda)
		result.Add(result, term)
	}
	return result
}

func CreateLocalSharesDKG(N, T int) ([]*Share, error) {

	if N <= 0 || T <= 0 || T > N {
		return nil, fmt.Errorf("invalid parameters: N=%d, T=%d; must have 0 < T <= N", N, T)
	}

	// Step 1: Simulate N nodes with their polynomials and shares
	type dkgNode struct {
		id         int
		polynomial []*big.Int
		shares     map[string]*big.Int // Shares to send to others
	}

	nodes := make([]*dkgNode, N)
	nodesList := make([]string, N)
	for i := 0; i < N; i++ {
		id := i + 1 // 1-based indexing
		nodesList[i] = strconv.Itoa(id)
		nodes[i] = &dkgNode{
			id:     id,
			shares: make(map[string]*big.Int),
		}
	}

	// Step 2: Generate polynomials (degree T-1, T coefficients)
	for _, node := range nodes {
		node.polynomial = make([]*big.Int, T)
		for i := 0; i < T; i++ {
			coef, err := rand.Int(rand.Reader, &curve.Order)
			if err != nil {
				return nil, fmt.Errorf("failed to generate coefficient: %v", err)
			}
			node.polynomial[i] = coef
		}

		// Generate shares for other nodes
		for _, targetID := range nodesList {
			if targetID == strconv.Itoa(node.id) {
				continue
			}
			x, err := strconv.Atoi(targetID)
			if err != nil {
				return nil, fmt.Errorf("failed to generate coefficient: %v", err)
			}
			share := EvaluatePolynomial(node.polynomial, big.NewInt(int64(x)))
			node.shares[targetID] = share
		}
	}

	// Step 3: Compute final shares for each node
	shares := make([]*Share, N)
	for i, node := range nodes {
		privateKey := new(big.Int)

		// Add received shares from other nodes
		for _, otherNode := range nodes {
			if otherNode.id == node.id {
				continue
			}
			share, exists := otherNode.shares[strconv.Itoa(node.id)]
			if exists {
				privateKey.Add(privateKey, share)
				privateKey.Mod(privateKey, &curve.Order)
			}
		}

		// Add own share
		ownShare := EvaluatePolynomial(node.polynomial, big.NewInt(int64(node.id)))
		privateKey.Add(privateKey, ownShare)
		privateKey.Mod(privateKey, &curve.Order)

		// Compute public key
		publicKey := new(twistededwards.PointAffine)
		publicKey.ScalarMultiplication(&curve.Base, privateKey)

		shares[i] = &Share{
			Index:      node.id,
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}
	}

	// Verify reconstruction
	masterPrivate := reconstructPrivateKey(shares, T)
	masterPublic := reconstructPublicKey(shares, T)
	derivedPublic := new(twistededwards.PointAffine)
	derivedPublic.ScalarMultiplication(&curve.Base, masterPrivate)

	fmt.Printf("\nReconstructed Master Private Key: %s\n", masterPrivate.String())
	fmt.Printf("Reconstructed Master Public Key - X=%s, Y=%s\n", masterPublic.X.String(), masterPublic.Y.String())
	fmt.Printf("Derived Master Public Key - X=%s, Y=%s\n", derivedPublic.X.String(), derivedPublic.Y.String())
	if masterPublic.Equal(derivedPublic) {
		fmt.Println("Verification successful: Reconstructed keys match!")
	} else {
		fmt.Println("Verification failed: Reconstructed keys do not match.")
	}

	return shares, nil
}

func TOPRFThresholdMul(idxs []int, elements []*twistededwards.PointAffine) *twistededwards.PointAffine {
	result := &twistededwards.PointAffine{}
	result.X.SetZero()
	result.Y.SetOne()

	for i := 0; i < len(elements); i++ {
		lambda, _ := LagrangeCoefficient(idxs[i], idxs)
		gki := &twistededwards.PointAffine{}
		gki.ScalarMultiplication(elements[i], lambda)
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
	sk, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		panic(err)
	}
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
