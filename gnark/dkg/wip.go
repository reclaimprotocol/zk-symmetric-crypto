package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

var TBNCurveOrder = func() *big.Int { order := twistededwards.GetEdwardsCurve().Order; return &order }()

// DLEQProof represents a non-interactive DLEQ proof
type DLEQProof struct {
	C, S *big.Int // Challenge and response
}

// Participant represents a single party in the JF-DKG protocol
type Participant struct {
	ID           int                           // Unique identifier for the participant
	Secret       *big.Int                      // Secret value chosen by the participant (OPRF key share)
	Coefficients []*big.Int                    // Polynomial coefficients for secret sharing
	Shares       map[int]*big.Int              // Shares generated for other participants
	Commitments  []*twistededwards.PointAffine // Public commitments to polynomial coefficients
}

// DKGState holds the global state of the JF-DKG process
type DKGState struct {
	Participants []*Participant
	Threshold    int // t: minimum number of shares to reconstruct secret
	NumParties   int // n: total number of participants
	PublicKey    *twistededwards.PointAffine
}

// NewDKGState initializes the DKG state with given parameters
func NewDKGState(n, t int) *DKGState {
	participants := make([]*Participant, n)
	for i := 0; i < n; i++ {
		participants[i] = &Participant{
			ID:           i + 1,
			Shares:       make(map[int]*big.Int),
			Coefficients: make([]*big.Int, t),
		}
	}

	return &DKGState{
		Participants: participants,
		Threshold:    t,
		NumParties:   n,
	}
}

// Stage 1: Each participant generates their secret and polynomial coefficients
func (s *DKGState) GenerateSecrets() error {
	for _, p := range s.Participants {
		secret, err := rand.Int(rand.Reader, TBNCurveOrder)
		if err != nil {
			return err
		}
		secret.Mod(secret, TBNCurveOrder)
		p.Secret = secret
		p.Coefficients[0] = secret

		for i := 1; i < s.Threshold; i++ {
			coeff := big.NewInt(int64(p.ID*10 + i))
			coeff.Mod(coeff, TBNCurveOrder)
			p.Coefficients[i] = coeff
		}
	}
	return nil
}

// Stage 2: Compute commitments
func (s *DKGState) ComputeCommitments() error {
	curve := twistededwards.GetEdwardsCurve()
	g := curve.Base
	for _, p := range s.Participants {
		// Commitments
		p.Commitments = make([]*twistededwards.PointAffine, s.Threshold)
		for i := 0; i < s.Threshold; i++ {
			p.Commitments[i] = &twistededwards.PointAffine{}
			p.Commitments[i].ScalarMultiplication(&g, p.Coefficients[i])
		}
	}
	return nil
}

// Stage 3: Each participant generates shares
func (s *DKGState) GenerateShares() error {
	for _, p := range s.Participants {
		for pid := 1; pid <= s.NumParties; pid++ {
			share := new(big.Int).Set(p.Coefficients[0])
			x := big.NewInt(int64(pid))
			for i := 1; i < s.Threshold; i++ {
				term := new(big.Int).Exp(x, big.NewInt(int64(i)), TBNCurveOrder)
				term.Mul(term, p.Coefficients[i])
				term.Mod(term, TBNCurveOrder)
				share.Add(share, term)
				share.Mod(share, TBNCurveOrder)
			}
			p.Shares[pid] = share
		}
	}
	return nil
}

// Stage 4: Verify shares
func (s *DKGState) VerifyShares() error {
	curve := twistededwards.GetEdwardsCurve()
	g := curve.Base

	for _, p := range s.Participants {
		// Verify shares
		for pid := 1; pid <= s.NumParties; pid++ {
			share := p.Shares[pid]
			x := big.NewInt(int64(pid))

			gShare := &twistededwards.PointAffine{}
			gShare = gShare.ScalarMultiplication(&g, share)
			rhs := &twistededwards.PointAffine{}
			for i := 0; i < s.Threshold; i++ {
				xi := new(big.Int).Exp(x, big.NewInt(int64(i)), TBNCurveOrder)
				commit := p.Commitments[i]
				tmp := &twistededwards.PointAffine{}
				tmp = tmp.ScalarMultiplication(commit, xi)
				if i == 0 {
					rhs = tmp
				} else {
					rhs = rhs.Add(rhs, tmp)
				}
			}
			if !gShare.Equal(rhs) {
				return fmt.Errorf("share verification failed for participant %d, share for %d", p.ID, pid)
			}
		}

	}
	return nil
}

// Stage 5: Compute final shares and public key
func (s *DKGState) ComputeFinalKey() error {
	curve := twistededwards.GetEdwardsCurve()
	g := curve.Base
	finalShares := make(map[int]*big.Int)
	for pid := 1; pid <= s.NumParties; pid++ {
		finalShare := big.NewInt(0)
		for _, p := range s.Participants {
			share := p.Shares[pid]
			finalShare.Add(finalShare, share)
			finalShare.Mod(finalShare, TBNCurveOrder)
		}
		finalShares[pid] = finalShare
	}

	totalSecret := big.NewInt(0)
	for _, p := range s.Participants {
		totalSecret.Add(totalSecret, p.Secret)
		totalSecret.Mod(totalSecret, TBNCurveOrder)
	}
	s.PublicKey = &twistededwards.PointAffine{}
	s.PublicKey = s.PublicKey.ScalarMultiplication(&g, totalSecret)
	return nil
}

// Main function to run the JF-DKG stages
func main() {
	state := NewDKGState(40, 20)
	stages := []struct {
		name string
		fn   func() error
	}{
		{"Generate Secrets", state.GenerateSecrets},
		{"Compute Commitments ", state.ComputeCommitments},
		{"Generate Shares", state.GenerateShares},
		{"Verify Shares ", state.VerifyShares},
		{"Compute Final Key", state.ComputeFinalKey},
	}

	for _, stage := range stages {
		fmt.Printf("Running stage: %s\n", stage.name)
		if err := stage.fn(); err != nil {
			fmt.Printf("Error in %s: %v\n", stage.name, err)
			return
		}
	}

	fmt.Printf("Public Key: (%X)\n", state.PublicKey.Marshal())
}
