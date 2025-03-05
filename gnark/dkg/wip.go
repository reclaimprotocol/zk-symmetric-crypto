package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Point represents an elliptic curve point (x, y)
type Point struct {
	X, Y *big.Int
}

// DLEQProof represents a non-interactive DLEQ proof
type DLEQProof struct {
	C, S *big.Int // Challenge and response
}

// Participant represents a single party in the JF-DKG protocol
type Participant struct {
	ID           int              // Unique identifier for the participant
	Secret       *big.Int         // Secret value chosen by the participant (OPRF key share)
	Coefficients []*big.Int       // Polynomial coefficients for secret sharing
	Shares       map[int]*big.Int // Shares generated for other participants
	Commitments  []Point          // Public commitments to polynomial coefficients
	OPRFOutput   Point            // OPRF evaluation: h^secret
	DLEQ         DLEQProof        // DLEQ proof for g^secret and h^secret
}

// DKGState holds the global state of the JF-DKG process
type DKGState struct {
	Participants []*Participant
	Threshold    int            // t: minimum number of shares to reconstruct secret
	NumParties   int            // n: total number of participants
	Curve        elliptic.Curve // Elliptic curve for public key generation
	P            *big.Int       // Order of the curve (prime modulus)
	Gx, Gy       *big.Int       // Generator point coordinates
	Hx, Hy       *big.Int       // OPRF input point (h)
	PublicKeyX   *big.Int       // Final shared public key X-coordinate
	PublicKeyY   *big.Int       // Final shared public key Y-coordinate
}

// NewDKGState initializes the DKG state with given parameters
func NewDKGState(n, t int) *DKGState {
	curve := elliptic.P256()
	p := curve.Params().N
	gx, gy := curve.Params().Gx, curve.Params().Gy
	// Fixed h for OPRF input (e.g., hash of "input" to point)
	hx, hy := curve.ScalarBaseMult(big.NewInt(42).Bytes()) // Deterministic h for demo

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
		Curve:        curve,
		P:            p,
		Gx:           gx,
		Gy:           gy,
		Hx:           hx,
		Hy:           hy,
	}
}

// Stage 1: Each participant generates their secret and polynomial coefficients (deterministic)
func (s *DKGState) GenerateSecrets() error {
	for _, p := range s.Participants {
		secret := big.NewInt(int64(p.ID * 10)) // Static secret: 10, 20, 30, 40
		secret.Mod(secret, s.P)
		p.Secret = secret
		p.Coefficients[0] = secret

		for i := 1; i < s.Threshold; i++ {
			coeff := big.NewInt(int64(p.ID*10 + i))
			coeff.Mod(coeff, s.P)
			p.Coefficients[i] = coeff
		}
	}
	return nil
}

// Stage 2: Compute commitments and OPRF output with DLEQ proof
func (s *DKGState) ComputeCommitmentsAndOPRF() error {
	for _, p := range s.Participants {
		// Commitments
		p.Commitments = make([]Point, s.Threshold)
		for i := 0; i < s.Threshold; i++ {
			x, y := s.Curve.ScalarBaseMult(p.Coefficients[i].Bytes())
			p.Commitments[i] = Point{X: x, Y: y}
		}

		// OPRF output: h^secret
		hx, hy := s.Curve.ScalarMult(s.Hx, s.Hy, p.Secret.Bytes())
		p.OPRFOutput = Point{X: hx, Y: hy}

		// DLEQ proof: prove g^secret and h^secret share the same secret
		w, err := rand.Int(rand.Reader, s.P)
		if err != nil {
			return fmt.Errorf("failed to generate w for DLEQ: %v", err)
		}
		// Compute A = g^w, B = h^w
		ax, ay := s.Curve.ScalarBaseMult(w.Bytes())
		bx, by := s.Curve.ScalarMult(s.Hx, s.Hy, w.Bytes())
		// Challenge c = H(g, h, g^secret, h^secret, A, B)
		hash := sha256.New()
		hash.Write(s.Gx.Bytes())
		hash.Write(s.Gy.Bytes())
		hash.Write(s.Hx.Bytes())
		hash.Write(s.Hy.Bytes())
		hash.Write(p.Commitments[0].X.Bytes())
		hash.Write(p.Commitments[0].Y.Bytes())
		hash.Write(p.OPRFOutput.X.Bytes())
		hash.Write(p.OPRFOutput.Y.Bytes())
		hash.Write(ax.Bytes())
		hash.Write(ay.Bytes())
		hash.Write(bx.Bytes())
		hash.Write(by.Bytes())
		c := new(big.Int).SetBytes(hash.Sum(nil))
		c.Mod(c, s.P)
		// Response s = w + c * secret mod P
		sVal := new(big.Int).Mul(c, p.Secret)
		sVal.Add(sVal, w)
		sVal.Mod(sVal, s.P)
		p.DLEQ = DLEQProof{C: c, S: sVal}
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
				term := new(big.Int).Exp(x, big.NewInt(int64(i)), s.P)
				term.Mul(term, p.Coefficients[i])
				term.Mod(term, s.P)
				share.Add(share, term)
				share.Mod(share, s.P)
			}
			p.Shares[pid] = share
		}
	}
	return nil
}

// Stage 4: Verify shares and DLEQ proofs
func (s *DKGState) VerifySharesAndDLEQ() error {
	for _, p := range s.Participants {
		// Verify shares
		for pid := 1; pid <= s.NumParties; pid++ {
			share := p.Shares[pid]
			x := big.NewInt(int64(pid))
			gShareX, gShareY := s.Curve.ScalarBaseMult(share.Bytes())
			rhsX, rhsY := big.NewInt(0), big.NewInt(0)
			for i := 0; i < s.Threshold; i++ {
				xi := new(big.Int).Exp(x, big.NewInt(int64(i)), s.P)
				commit := p.Commitments[i]
				xTmp, yTmp := s.Curve.ScalarMult(commit.X, commit.Y, xi.Bytes())
				if i == 0 {
					rhsX, rhsY = xTmp, yTmp
				} else {
					rhsX, rhsY = s.Curve.Add(rhsX, rhsY, xTmp, yTmp)
				}
			}
			if gShareX.Cmp(rhsX) != 0 || gShareY.Cmp(rhsY) != 0 {
				return fmt.Errorf("share verification failed for participant %d, share for %d", p.ID, pid)
			}
		}

		// Verify DLEQ proof
		// Compute g^s and h^s
		gsX, gsY := s.Curve.ScalarBaseMult(p.DLEQ.S.Bytes())
		hsX, hsY := s.Curve.ScalarMult(s.Hx, s.Hy, p.DLEQ.S.Bytes())
		// Compute (g^secret)^c and (h^secret)^c
		gSecretX, gSecretY := p.Commitments[0].X, p.Commitments[0].Y
		gscX, gscY := s.Curve.ScalarMult(gSecretX, gSecretY, p.DLEQ.C.Bytes())
		hSecretX, hSecretY := p.OPRFOutput.X, p.OPRFOutput.Y
		hscX, hscY := s.Curve.ScalarMult(hSecretX, hSecretY, p.DLEQ.C.Bytes())
		// Compute A = g^s / (g^secret)^c = g^s + (-(g^secret)^c)
		gscYNeg := new(big.Int).Neg(gscY)
		gscYNeg.Mod(gscYNeg, s.Curve.Params().P) // Modulo field prime
		ax, ay := s.Curve.Add(gsX, gsY, gscX, gscYNeg)
		// Compute B = h^s / (h^secret)^c = h^s + (-(h^secret)^c)
		hscYNeg := new(big.Int).Neg(hscY)
		hscYNeg.Mod(hscYNeg, s.Curve.Params().P)
		bx, by := s.Curve.Add(hsX, hsY, hscX, hscYNeg)
		// Recompute challenge c' = H(g, h, g^secret, h^secret, A, B)
		hash := sha256.New()
		hash.Write(s.Gx.Bytes())
		hash.Write(s.Gy.Bytes())
		hash.Write(s.Hx.Bytes())
		hash.Write(s.Hy.Bytes())
		hash.Write(gSecretX.Bytes())
		hash.Write(gSecretY.Bytes())
		hash.Write(hSecretX.Bytes())
		hash.Write(hSecretY.Bytes())
		hash.Write(ax.Bytes())
		hash.Write(ay.Bytes())
		hash.Write(bx.Bytes())
		hash.Write(by.Bytes())
		cPrime := new(big.Int).SetBytes(hash.Sum(nil))
		cPrime.Mod(cPrime, s.P)
		if cPrime.Cmp(p.DLEQ.C) != 0 {
			return fmt.Errorf("DLEQ verification failed for participant %d", p.ID)
		}
	}
	return nil
}

// Stage 5: Compute final shares and public key
func (s *DKGState) ComputeFinalKey() error {
	finalShares := make(map[int]*big.Int)
	for pid := 1; pid <= s.NumParties; pid++ {
		finalShare := big.NewInt(0)
		for _, p := range s.Participants {
			share := p.Shares[pid]
			finalShare.Add(finalShare, share)
			finalShare.Mod(finalShare, s.P)
		}
		finalShares[pid] = finalShare
	}

	totalSecret := big.NewInt(0)
	for _, p := range s.Participants {
		totalSecret.Add(totalSecret, p.Secret)
		totalSecret.Mod(totalSecret, s.P)
	}
	s.PublicKeyX, s.PublicKeyY = s.Curve.ScalarBaseMult(totalSecret.Bytes())
	return nil
}

// Main function to run the JF-DKG stages
func main() {
	state := NewDKGState(4, 2)
	stages := []struct {
		name string
		fn   func() error
	}{
		{"Generate Secrets", state.GenerateSecrets},
		{"Compute Commitments and OPRF", state.ComputeCommitmentsAndOPRF},
		{"Generate Shares", state.GenerateShares},
		{"Verify Shares and DLEQ", state.VerifySharesAndDLEQ},
		{"Compute Final Key", state.ComputeFinalKey},
	}

	for _, stage := range stages {
		fmt.Printf("Running stage: %s\n", stage.name)
		if err := stage.fn(); err != nil {
			fmt.Printf("Error in %s: %v\n", stage.name, err)
			return
		}
	}

	fmt.Printf("Public Key: (%s, %s)\n", state.PublicKeyX.Text(16), state.PublicKeyY.Text(16))
}
