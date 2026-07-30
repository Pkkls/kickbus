package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

// What an invalid signature costs the attacker versus what it costs us.
// The webhook URL is public: anyone can hammer it.
func BenchmarkVerifySignature(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	body := make([]byte, 512)
	ts := time.Now().UTC().Format(time.RFC3339)
	sum := sha256.Sum256([]byte("msg." + ts + "." + string(body)))
	raw, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	sig := base64.StdEncoding.EncodeToString(raw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifySignature(&priv.PublicKey, "msg", ts, body, sig)
	}
}

func BenchmarkVerifyGarbage(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	body := make([]byte, 512)
	ts := time.Now().UTC().Format(time.RFC3339)
	junk := base64.StdEncoding.EncodeToString(make([]byte, 256))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifySignature(&priv.PublicKey, "msg", ts, body, junk)
	}
}
