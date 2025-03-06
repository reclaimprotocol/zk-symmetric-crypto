package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
)

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
	PublicKey      eddsa.PublicKey               // Public key g^s_i
}

// DKGState represents the entire DKG system
type DKGState struct {
	Participants []*DKGParticipant
	Curve        *twistededwards.CurveParams
}

// NewDKGState initializes a new DKG state with n participants and threshold t
func NewDKGState(n, t int) *DKGState {
	curve := twistededwards.GetEdwardsCurve()
	state := &DKGState{
		Participants: make([]*DKGParticipant, n),
		Curve:        &curve,
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

// Stage 1: Generate secret polynomials and commitments
func (state *DKGState) GeneratePolynomials() {
	for _, p := range state.Participants {
		// Generate random secret
		p.Secret, _ = rand.Int(rand.Reader, &state.Curve.Order)

		// Create (t-1)-degree polynomial: f(x) = a_0 + a_1*x + ... + a_(t-1)*x^(t-1)
		p.Polynomial = make([]*big.Int, p.Threshold)
		p.Polynomial[0] = new(big.Int).Set(p.Secret)
		for i := 1; i < p.Threshold; i++ {
			p.Polynomial[i], _ = rand.Int(rand.Reader, &state.Curve.Order)
		}

		// Generate public commitments C_i = g^a_i
		p.PublicCommits = make([]*twistededwards.PointAffine, p.Threshold)
		for i := 0; i < p.Threshold; i++ {
			p.PublicCommits[i] = new(twistededwards.PointAffine)
			p.PublicCommits[i].ScalarMultiplication(&state.Curve.Base, p.Polynomial[i])
		}
	}
}

// Stage 2: Generate and "distribute" shares
func (state *DKGState) GenerateShares() {
	for _, sender := range state.Participants {
		for _, receiver := range state.Participants {
			share := evaluatePolynomial(sender.Polynomial, big.NewInt(int64(receiver.ID)), &state.Curve.Order)
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
			lhs := new(twistededwards.PointAffine).ScalarMultiplication(&state.Curve.Base, share)
			rhs := new(twistededwards.PointAffine)
			rhs.X.SetZero()
			rhs.Y.SetOne()
			x := big.NewInt(int64(p.ID))
			for i := 0; i < sender.Threshold; i++ {
				xPow := new(big.Int).Exp(x, big.NewInt(int64(i)), &state.Curve.Order)
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
		for senderID, share := range p.ReceivedShares {
			secretShare.Add(secretShare, share)
			fmt.Printf("Participant %d: Share from %d = %s, Running SecretShare = %s\n",
				p.ID, senderID, share.String(), secretShare.String())
		}
		secretShare.Mod(secretShare, &state.Curve.Order)
		p.SecretShare = secretShare
		p.PublicKey.A = *new(twistededwards.PointAffine).ScalarMultiplication(&state.Curve.Base, secretShare)
		fmt.Printf("Participant %d: Final Secret Share = %s\n", p.ID, secretShare.String())
	}
}

// Reconstruct master public key from share public keys
func (state *DKGState) ReconstructMasterPublicKey(participantIDs []int) *twistededwards.PointAffine {
	if len(participantIDs) < state.Participants[0].Threshold {
		fmt.Println("Not enough participants to reconstruct master public key")
		return nil
	}

	result := new(twistededwards.PointAffine)
	result.X.SetZero()
	result.Y.SetOne()

	points := make(map[int]*twistededwards.PointAffine)
	for _, id := range participantIDs[:state.Participants[0].Threshold] {
		p := state.Participants[id-1]
		points[p.ID] = &p.PublicKey.A
	}

	for j := range points {
		lambda := lagrangeCoefficient(j, points, big.NewInt(0), &state.Curve.Order)
		term := new(twistededwards.PointAffine).ScalarMultiplication(points[j], lambda)
		result.Add(result, term)
		fmt.Printf("Participant %d: Lambda = %s\n", j, lambda.String())
	}
	return result
}

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
	if denInv == nil {
		panic("Modular inverse does not exist")
	}
	return new(big.Int).Mod(new(big.Int).Mul(num, denInv), modulus)
}

func main() {
	n := 4
	t := 3
	dkg := NewDKGState(n, t)

	fmt.Println("Stage 1: Generating polynomials and commitments...")
	dkg.GeneratePolynomials()

	fmt.Println("Stage 2: Generating shares...")
	dkg.GenerateShares()

	fmt.Println("Stage 3: Verifying shares...")
	if err := dkg.VerifyShares(); err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}

	fmt.Println("Stage 4: Computing final keys...")
	dkg.ComputeFinalKeys()

	for _, p := range dkg.Participants {
		fmt.Printf("Participant %d Public Key X: %s\n", p.ID, p.PublicKey.A.X.String())
	}

	fmt.Println("Reconstructing Master Public Key...")
	participantIDs := []int{1, 2, 3}
	masterPubKey := dkg.ReconstructMasterPublicKey(participantIDs)
	if masterPubKey != nil {
		fmt.Printf("Master Public Key X: %s\n", masterPubKey.X.String())
	}

	groupSecret := big.NewInt(0)
	for _, p := range dkg.Participants {
		groupSecret.Add(groupSecret, p.Secret)
	}
	groupSecret.Mod(groupSecret, &dkg.Curve.Order)
	actualMasterPubKey := new(twistededwards.PointAffine).ScalarMultiplication(&dkg.Curve.Base, groupSecret)
	fmt.Printf("Actual Master Public Key X: %s\n", actualMasterPubKey.X.String())
}
