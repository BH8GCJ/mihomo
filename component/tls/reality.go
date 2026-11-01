package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

const (
	RealityMaxShortIDLen = 8

	// REALITY ClientHello session ID layout (same as Xray-core):
	//   [0:3] client version, [3] reserved, [4:8] Unix timestamp, [8:16] short ID.
	// Xray-core v26.7.11 .. v26.9.7 defaulted minClientVer to 26.3.27, so clients
	// that still advertise the old 1.8.2 version are rejected as well.
	realityClientVersionX byte = 26
	realityClientVersionY byte = 3
	realityClientVersionZ byte = 27
)

type RealityConfig struct {
	PublicKey *ecdh.PublicKey
	ShortID   [RealityMaxShortIDLen]byte

	SupportX25519MLKEM768 bool
}

// buildRealitySessionID assembles the 32-byte ClientHello session ID that
// REALITY uses to carry the client version, timestamp and short ID. The layout
// must match Xray-core's server parser (plainText[0:3] version, [3] reserved,
// [4:8] big-endian Unix timestamp, [8:16] short ID).
func buildRealitySessionID(shortID [RealityMaxShortIDLen]byte, unixTime int64) [32]byte {
	var sessionID [32]byte
	sessionID[0] = realityClientVersionX
	sessionID[1] = realityClientVersionY
	sessionID[2] = realityClientVersionZ
	sessionID[3] = 0 // reserved
	binary.BigEndian.PutUint32(sessionID[4:8], uint32(unixTime))
	copy(sessionID[8:], shortID[:])
	return sessionID
}

func GetRealityConn(ctx context.Context, conn net.Conn, fingerprint UClientHelloID, serverName string, realityConfig *RealityConfig) (net.Conn, error) {
	for retry := 0; ; retry++ {
		verifier := &realityVerifier{
			serverName: serverName,
		}
		uConfig := &utls.Config{
			Time:                   ntp.Now,
			ServerName:             serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       verifier.VerifyConnection,
		}

		// Xray-core >= v26.9.8 requires X25519MLKEM768 in the ClientHello. uTLS
		// generates key share data only inside ApplyPreset, which must run before
		// the hello is built, so use HelloCustom and apply the augmented spec.
		// Random/randomized fingerprints have no static spec; keep the old path.
		helloID := fingerprint
		addMLKEM := realityConfig.SupportX25519MLKEM768
		if addMLKEM {
			if _, err := utls.UTLSIdToSpec(fingerprint); err != nil {
				addMLKEM = false
				log.Warnln("REALITY: fingerprint %s has no static ClientHello spec, X25519MLKEM768 cannot be added", fingerprint.Client)
			} else {
				helloID = utls.HelloCustom
			}
		}
		uConn := utls.UClient(conn, uConfig, helloID)
		verifier.UConn = uConn

		var err error
		switch {
		case addMLKEM:
			err = BuildAddedX25519MLKEM768HandshakeState(uConn, fingerprint)
		case realityConfig.SupportX25519MLKEM768:
			err = uConn.BuildHandshakeState()
		default: // old REALITY server that does not support X25519MLKEM768
			err = BuildRemovedX25519MLKEM768HandshakeState(uConn)
		}
		if err != nil {
			return nil, err
		}

		hello := uConn.HandshakeState.Hello
		// The REALITY AEAD authenticates the ClientHello with the session ID
		// field zeroed (the server zeros it before Open), so clear the raw field
		// first and only copy the sealed session ID in after sealing.
		copy(hello.Raw[39:], make([]byte, 32)) // the fixed location of session ID
		sessionID := buildRealitySessionID(realityConfig.ShortID, ntp.Now().Unix())
		hello.SessionId = sessionID[:]

		//log.Debugln("REALITY hello.sessionId[:16]: %v", hello.SessionId[:16])

		keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
		if keyShareKeys == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil keyShareKeys")
			}
			continue // retry
		}
		ecdheKey := keyShareKeys.Ecdhe
		if ecdheKey == nil {
			ecdheKey = keyShareKeys.MlkemEcdhe
		}
		if ecdheKey == nil {
			// WTF???
			if retry > 2 {
				return nil, errors.New("nil ecdheKey")
			}
			continue // retry
		}
		authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
		if err != nil {
			return nil, err
		}
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aeadCipher, _ := cipher.NewGCM(aesBlock)
		aeadCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)
		//log.Debugln("REALITY hello.sessionId: %v", hello.SessionId)
		//log.Debugln("REALITY uConn.AuthKey: %v", authKey)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v, AEAD: %T", verifier.verified, aeadCipher)

		if !verifier.verified {
			go realityClientFallback(uConn, uConfig.ServerName, fingerprint)
			return nil, errors.New("REALITY authentication failed")
		}

		return uConn, nil
	}
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	request, err := http.NewRequest("GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", randv2.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	//_, _ = io.Copy(io.Discard, response.Body)
	time.Sleep(time.Duration(5+randv2.IntN(10)) * time.Second)
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	log.Debugln("REALITY localAddr: %v is using X25519MLKEM768 for TLS' communication: %v", c.RemoteAddr(), c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
	certs := state.PeerCertificates
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
