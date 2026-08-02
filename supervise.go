package main

// Supervision des boucles de fond.
//
// Deux goroutines tournent pour toute la duree du processus : le rafraichissement
// de la cle publique et la reparation des abonnements. Ni l'une ni l'autre
// n'avait de `recover`, donc un panic dans l'une tuait le processus entier, y
// compris la reception des webhooks et la diffusion SSE, pour une panne dans un
// travail d'entretien.
//
// Le reflexe est d'ajouter `defer func(){ recover() }()`. Ce serait pire. La
// goroutine mourrait quand meme, en silence : le processus resterait debout,
// /health continuerait de repondre, et le rafraichissement de cle serait
// simplement arrete pour toujours. On echangerait un crash bruyant contre une
// degradation muette, qui est exactement le mode de panne que ce depot passe
// son temps a documenter.
//
// Donc : on recupere, on RELANCE, et on laisse une trace lisible de l'exterieur.
// Un panic n'est jamais efface, il devient un chiffre dans /health.

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sync/atomic"
	"time"
)

// backgroundHealth est ce que /health expose des boucles de fond.
type backgroundHealth struct {
	panics   atomic.Int64
	lastFail atomic.Pointer[string]
}

func (b *backgroundHealth) record(name string, v any, stack []byte) {
	b.panics.Add(1)
	msg := fmt.Sprintf("%s: %v", name, v)
	b.lastFail.Store(&msg)
	// La pile part dans le journal, pas dans /health : /health est lu par des
	// machines et doit rester court.
	log.Printf("background loop %s panicked and is being restarted: %v\n%s",
		name, v, stack)
}

// runOnce execute fn et rend false si elle a panique.
func runOnce(name string, bg *backgroundHealth, fn func()) (clean bool) {
	defer func() {
		if v := recover(); v != nil {
			bg.record(name, v, debug.Stack())
			clean = false
		}
	}()
	fn()
	return true
}

// supervise relance fn tant que le contexte est vivant.
//
// Le repli evite qu'un panic immediat et repete ne devienne une boucle chaude
// qui mange la carte : sur 128 Mo, une goroutine qui panique en continu coute
// plus cher que le travail qu'elle rate.
func supervise(ctx context.Context, name string, bg *backgroundHealth, fn func()) {
	delay := time.Second
	for {
		if runOnce(name, bg, fn) {
			return // sortie normale : le contexte est termine
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < time.Minute {
			delay *= 2
		}
	}
}
