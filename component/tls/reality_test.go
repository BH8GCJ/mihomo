package tls

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	utls "github.com/metacubex/utls"
)

func TestBuildRealitySessionID(t *testing.T) {
	shortID := [RealityMaxShortIDLen]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	const unixTime = 0x12345678
	sessionID := buildRealitySessionID(shortID, unixTime)

	if got, want := len(sessionID), 32; got != want {
		t.Fatalf("session ID length = %d, want %d", got, want)
	}
	if got, want := sessionID[:3], []byte{26, 3, 27}; !bytes.Equal(got, want) {
		t.Errorf("client version = %v, want %v", got, want)
	}
	if sessionID[3] != 0 {
		t.Errorf("reserved byte = %d, want 0", sessionID[3])
	}
	if got, want := binary.BigEndian.Uint32(sessionID[4:8]), uint32(unixTime); got != want {
		t.Errorf("timestamp = %#x, want %#x", got, want)
	}
	if got := sessionID[8:16]; !bytes.Equal(got, shortID[:]) {
		t.Errorf("short ID = %v, want %v", got, shortID[:])
	}
}

func TestBuildAddedX25519MLKEM768HandshakeState(t *testing.T) {
	fingerprints := []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"firefox", utls.HelloFirefox_Auto},
		{"safari", utls.HelloSafari_Auto},
		{"ios", utls.HelloIOS_Auto},
		{"edge", utls.HelloEdge_Auto},
		{"qq", utls.HelloQQ_Auto},
		{"chrome", utls.HelloChrome_Auto},
	}

	for _, fingerprint := range fingerprints {
		t.Run(fingerprint.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			uConn := utls.UClient(client, &utls.Config{
				ServerName:         "example.com",
				InsecureSkipVerify: true,
			}, utls.HelloCustom)
			if err := BuildAddedX25519MLKEM768HandshakeState(uConn, fingerprint.id); err != nil {
				t.Fatalf("build handshake state: %v", err)
			}

			if !hasMLKEMCurve(uConn.Extensions) {
				t.Error("X25519MLKEM768 is missing from supported curves")
			}
			keyShares := findKeyShareExtension(uConn.Extensions)
			if keyShares == nil || len(keyShares.KeyShares) == 0 {
				t.Fatal("key share extension is empty")
			}
			mlkemIndex, x25519Index := -1, -1
			for i, share := range keyShares.KeyShares {
				if share.Group == utls.X25519MLKEM768 && mlkemIndex == -1 {
					mlkemIndex = i
				}
				if share.Group == utls.X25519 && x25519Index == -1 {
					x25519Index = i
				}
			}
			if mlkemIndex == -1 {
				t.Fatal("X25519MLKEM768 key share is missing")
			}
			if x25519Index != -1 && mlkemIndex > x25519Index {
				t.Errorf("X25519MLKEM768 key share (index %d) must precede X25519 (index %d)", mlkemIndex, x25519Index)
			}
			// ML-KEM-768 encapsulation key (1184 bytes) || X25519 public key (32 bytes).
			if got, want := len(keyShares.KeyShares[mlkemIndex].Data), 1184+32; got != want {
				t.Errorf("ML-KEM key share length = %d, want %d", got, want)
			}
			keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
			if keyShareKeys == nil || (keyShareKeys.Ecdhe == nil && keyShareKeys.MlkemEcdhe == nil) {
				t.Error("no TLS 1.3 key share private key was generated")
			}
		})
	}
}

func TestBuildAddedX25519MLKEM768HandshakeStateIdempotent(t *testing.T) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	var before int
	for _, extension := range spec.Extensions {
		if keyShares, ok := extension.(*utls.KeyShareExtension); ok {
			for _, share := range keyShares.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					before++
				}
			}
		}
	}
	if before == 0 {
		t.Fatal("chrome fingerprint unexpectedly has no X25519MLKEM768 key share")
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := utls.UClient(client, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := BuildAddedX25519MLKEM768HandshakeState(uConn, utls.HelloChrome_Auto); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}

	var after int
	for _, extension := range uConn.Extensions {
		if keyShares, ok := extension.(*utls.KeyShareExtension); ok {
			for _, share := range keyShares.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					after++
				}
			}
		}
	}
	if after != before {
		t.Errorf("X25519MLKEM768 key share count changed: got %d, want %d", after, before)
	}
}

func hasMLKEMCurve(extensions []utls.TLSExtension) bool {
	for _, extension := range extensions {
		if curves, ok := extension.(*utls.SupportedCurvesExtension); ok {
			for _, curve := range curves.Curves {
				if curve == utls.X25519MLKEM768 {
					return true
				}
			}
		}
	}
	return false
}

func findKeyShareExtension(extensions []utls.TLSExtension) *utls.KeyShareExtension {
	for _, extension := range extensions {
		if keyShares, ok := extension.(*utls.KeyShareExtension); ok {
			return keyShares
		}
	}
	return nil
}

func TestBuildAddedX25519MLKEM768HandshakeStateUnsupportedFingerprint(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := utls.UClient(client, &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := BuildAddedX25519MLKEM768HandshakeState(uConn, utls.HelloAndroid_11_OkHttp); err == nil {
		t.Error("expected an error for a fingerprint without TLS 1.3 key shares")
	}
}
