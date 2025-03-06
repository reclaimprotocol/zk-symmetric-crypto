package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

var curve = twistededwards.GetEdwardsCurve()

// DKGParticipant represents a single participant in the DKG protocol
type DKGParticipant struct {
	ID             int                           // Unique identifier for the participant
	Threshold      int                           // Threshold t for t-out-of-n sharing
	NumParties     int                           // Total number n of participants
	Secret         *big.Int                      // Participant's secret value
	Polynomial     []*big.Int                    // Coefficients of the secret polynomial
	PublicCommits  []*twistededwards.PointAffine // Public commitments to polynomial coefficients
	Shares         map[int]*big.Int              // Shares generated for other participants
	ReceivedShares map[int]*big.Int              // Shares received from other participants
	SecretShare    *big.Int                      // Final secret share s_i
	PublicKey      *twistededwards.PointAffine   // Public key g^s_i
}

// DKGState represents the entire DKG system
type DKGState struct {
	Participants []*DKGParticipant
}

// NewDKGState initializes a new DKG state with n participants and threshold t
func NewDKGState(n, t int) *DKGState {

	state := &DKGState{
		Participants: make([]*DKGParticipant, n),
	}
	for i := 0; i < n; i++ {
		state.Participants[i] = &DKGParticipant{
			ID:             i + 1,
			Threshold:      t,
			NumParties:     n,
			Shares:         make(map[int]*big.Int),
			ReceivedShares: make(map[int]*big.Int),
		}
	}
	return state
}

// GeneratePolynomials Stage 1: Generate secret polynomials and commitments
func (state *DKGState) GeneratePolynomials() {
	for _, p := range state.Participants {

		secret, err := rand.Int(rand.Reader, &curve.Order)
		if err != nil {
			panic(err)
		}

		p.Secret = secret
		p.Polynomial = make([]*big.Int, p.Threshold)
		p.Polynomial[0] = new(big.Int).Set(p.Secret)
		for i := 1; i < p.Threshold; i++ {
			poly, e := rand.Int(rand.Reader, &curve.Order)
			if e != nil {
				panic(e)
			}
			p.Polynomial[i] = poly
		}
		p.PublicCommits = make([]*twistededwards.PointAffine, p.Threshold)
		for i := 0; i < p.Threshold; i++ {
			p.PublicCommits[i] = new(twistededwards.PointAffine)
			p.PublicCommits[i].ScalarMultiplication(&curve.Base, p.Polynomial[i])
		}
	}
}

// GenerateShares Stage 2: Generate and "distribute" shares
func (state *DKGState) GenerateShares() {
	for _, sender := range state.Participants {
		for _, receiver := range state.Participants {
			share := evaluatePolynomial(sender.Polynomial, big.NewInt(int64(receiver.ID)), &curve.Order)
			sender.Shares[receiver.ID] = share
			receiver.ReceivedShares[sender.ID] = share
		}
	}
}

// Stage 3: Verify received shares
func (state *DKGState) VerifyShares() error {
	for _, p := range state.Participants {
		for senderID, share := range p.ReceivedShares {
			sender := state.Participants[senderID-1]
			lhs := new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, share)
			rhs := new(twistededwards.PointAffine)
			rhs.X.SetZero()
			rhs.Y.SetOne()
			x := big.NewInt(int64(p.ID))
			for i := 0; i < sender.Threshold; i++ {
				xPow := new(big.Int).Exp(x, big.NewInt(int64(i)), &curve.Order)
				term := new(twistededwards.PointAffine).ScalarMultiplication(sender.PublicCommits[i], xPow)
				rhs.Add(rhs, term)
			}
			if !lhs.Equal(rhs) {
				return fmt.Errorf("share verification failed for participant %d from %d", p.ID, senderID)
			}
		}
	}
	return nil
}

// Stage 4: Compute final keys
func (state *DKGState) ComputeFinalKeys() {
	for _, p := range state.Participants {
		secretShare := big.NewInt(0)
		for _, share := range p.ReceivedShares {
			secretShare.Add(secretShare, share)
			// fmt.Printf("Participant %d: Share from %d = %s, Running SecretShare = %s\n",
			// 	p.ID, senderID, share.String(), secretShare.String())
		}
		secretShare.Mod(secretShare, &curve.Order)
		p.SecretShare = secretShare
		p.PublicKey = new(twistededwards.PointAffine).ScalarMultiplication(&curve.Base, secretShare)
		// fmt.Printf("Participant %d: Final Secret Share = %s\n", p.ID, secretShare.String())
	}
}

// Reconstruct master public key from share public keys
/*func (state *DKGState) ReconstructMasterPublicKey(participantIDs []int) *twistededwards.PointAffine {
	if len(participantIDs) < state.Participants[0].Threshold {
		fmt.Println("Not enough participants to reconstruct master public key")
		return nil
	}

	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()

	// Use only t participants
	points := make(map[int]*twistededwards.PointAffine)
	for _, id := range participantIDs[:state.Participants[0].Threshold] {
		p := state.Participants[id-1]
		points[p.ID] = p.PublicKey
	}

	for j := range points {
		lambda := lagrangeCoefficient(j, points, big.NewInt(0), &curve.Order)
		term := new(twistededwards.PointAffine).ScalarMultiplication(points[j], lambda)
		result.Add(result, term)
		// fmt.Printf("Participant %d: Lambda = %s\n", j, lambda.String())
	}
	return result
}*/

// Evaluate polynomial at point x using Horner's method
func evaluatePolynomial(coeffs []*big.Int, x, modulus *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coeffs[i])
		result.Mod(result, modulus)
	}
	return result
}

// Compute Lagrange coefficient for point j at evaluation point x
/*func lagrangeCoefficient(j int, points map[int]*twistededwards.PointAffine, x, modulus *big.Int) *big.Int {
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
	if denInv == nil {
		panic("Modular inverse does not exist")
	}
	return new(big.Int).Mod(new(big.Int).Mul(num, denInv), modulus)
}*/

func DKG(n, t int) []*Share {

	dkg := NewDKGState(n, t)

	fmt.Println("Stage 1: Generating polynomials and commitments...")
	dkg.GeneratePolynomials()

	fmt.Println("Stage 2: Generating shares...")
	dkg.GenerateShares()

	fmt.Println("Stage 3: Verifying shares...")
	if err := dkg.VerifyShares(); err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		panic(err)
	}

	fmt.Println("Stage 4: Computing final keys...")
	dkg.ComputeFinalKeys()

	shares := make([]*Share, n)
	for i := 0; i < n; i++ {
		shares[i] = &Share{
			Index:      dkg.Participants[i].ID,
			PrivateKey: dkg.Participants[i].SecretShare,
			PublicKey:  dkg.Participants[i].PublicKey,
		}
	}

	return shares

}
