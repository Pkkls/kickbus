package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Un panic dans une boucle de fond ne doit ni tuer le processus ni disparaitre.
// Les deux moities comptent : sans le redemarrage on garde un crash, sans la
// trace on le remplace par une panne muette, ce qui est pire.
func TestSupervisedLoopRestartsAndIsCounted(t *testing.T) {
	var bg backgroundHealth
	var calls atomic.Int64
	done := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go supervise(ctx, "boucle-de-test", &bg, func() {
		switch calls.Add(1) {
		case 1, 2:
			panic("panne simulee")
		default:
			close(done)
			<-ctx.Done() // se comporte comme une vraie boucle : ne rend qu'a l'arret
		}
	})

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("la boucle n'a pas redemarre, %d appel(s)", calls.Load())
	}
	if got := bg.panics.Load(); got != 2 {
		t.Fatalf("panics comptes = %d, attendu 2", got)
	}
	last := bg.lastFail.Load()
	if last == nil || !strings.Contains(*last, "boucle-de-test") {
		t.Fatalf("le dernier panic ne nomme pas sa boucle: %v", last)
	}
}

// Temoin : une boucle qui se termine proprement ne doit rien compter et ne doit
// surtout pas etre relancee. Sans ce cas, un compteur bloque a zero et une
// supervision inerte rendent la meme reponse.
func TestCleanLoopIsNotRestartedAndCountsNothing(t *testing.T) {
	var bg backgroundHealth
	var calls atomic.Int64

	supervise(context.Background(), "boucle-propre", &bg, func() {
		calls.Add(1)
	})

	if got := calls.Load(); got != 1 {
		t.Fatalf("appels = %d, attendu 1 (pas de relance sur sortie propre)", got)
	}
	if got := bg.panics.Load(); got != 0 {
		t.Fatalf("panics = %d sur une boucle qui n'a pas panique", got)
	}
	if bg.lastFail.Load() != nil {
		t.Fatal("une boucle propre a laisse une trace d'echec")
	}
}

// /health doit rester silencieux tant que rien n'a panique, puis le dire.
// Un champ toujours present a zero se lit comme du bruit et finit ignore.
func TestHealthSurfacesBackgroundPanicsOnlyWhenTheyHappen(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{hub: NewHub(0), keys: newKeyHolder(&priv.PublicKey), start: time.Now()}

	read := func() map[string]any {
		rec := httptest.NewRecorder()
		srv.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		b, _ := io.ReadAll(rec.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("health illisible: %v (%s)", err, b)
		}
		return m
	}

	before := read()
	if _, present := before["background_panics"]; present {
		t.Fatal("temoin: le champ apparait alors que rien n'a panique")
	}

	srv.bg.record("boucle-x", "boum", []byte("pile"))
	after := read()
	if after["background_panics"] != float64(1) {
		t.Fatalf("background_panics = %v, attendu 1", after["background_panics"])
	}
	msg, _ := after["background_last_panic"].(string)
	if !strings.Contains(msg, "boucle-x") || !strings.Contains(msg, "boum") {
		t.Fatalf("background_last_panic = %q", msg)
	}
}
