package http

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// secondaryKeyShares holds the private keys of the classical key shares
// after the first in a ClientHello, by group.
//
// uTLS keeps the private key of only the first classical (ECDHE) key share
// it generates. Firefox sends two, X25519 and P-256, so with uTLS alone a
// server that selects P-256 fails the handshake with "invalid server key
// share". fphttp generates the later shares itself, which uTLS sends as
// given, and hands uTLS the matching private key once the ServerHello names
// the group. The ClientHello is unchanged: every share keeps its group,
// position, and length, and carries fresh key material as before.
type secondaryKeyShares map[utls.CurveID]*ecdh.PrivateKey

// generateSecondaryKeyShares fills the key exchange data of every classical
// key share in spec after the first and returns their private keys. It
// leaves the first classical share, hybrid shares, GREASE shares, and shares
// that already carry data to uTLS.
func generateSecondaryKeyShares(spec *utls.ClientHelloSpec) (secondaryKeyShares, error) {
	keys := make(secondaryKeyShares)

	for _, extension := range spec.Extensions {
		keyShare, ok := extension.(*utls.KeyShareExtension)
		if !ok {
			continue
		}

		if err := keys.generate(keyShare.KeyShares); err != nil {
			return nil, err
		}
	}

	return keys, nil
}

// generate fills the classical shares after the first in shares, recording
// their private keys.
func (keys secondaryKeyShares) generate(shares []utls.KeyShare) error {
	classical := 0

	for index := range shares {
		share := &shares[index]

		curve, ok := classicalCurve(share.Group)
		if !ok {
			continue
		}

		classical++
		if classical == 1 || len(share.Data) > 0 {
			continue
		}

		key, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate %v key share: %w", share.Group, err)
		}

		share.Data = key.PublicKey().Bytes()
		keys[share.Group] = key
	}

	return nil
}

// use gives conn the private key of group when it is one of keys. It must
// run after the ServerHello arrives and before uTLS computes the shared
// secret: uTLS copies its key share keys into the TLS 1.3 handshake only
// after it reads the whole ServerHello. Audit this ordering whenever the
// uTLS version changes.
func (keys secondaryKeyShares) use(conn *utls.UConn, group utls.CurveID) {
	key, ok := keys[group]
	if !ok {
		return
	}

	state := conn.HandshakeState.State13.KeyShareKeys
	if state == nil {
		return
	}

	state.Ecdhe = key
}

// classicalCurve returns the elliptic curve of a classical key exchange
// group.
func classicalCurve(group utls.CurveID) (ecdh.Curve, bool) {
	switch group {
	case utls.X25519:
		return ecdh.X25519(), true

	case utls.CurveP256:
		return ecdh.P256(), true

	case utls.CurveP384:
		return ecdh.P384(), true

	case utls.CurveP521:
		return ecdh.P521(), true

	default:
		return nil, false
	}
}
