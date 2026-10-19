package events

import (
	"sync"

	"corkboard/internal/model"
)

type Broker struct {
	mu   sync.Mutex
	subs map[chan model.Event]struct{}
}

func NewBroker() *Broker {
	return &Broker{subs: make(map[chan model.Event]struct{})}
}

const bufSize = 256

func (b *Broker) Subscribe() (<-chan model.Event, func()) {
	ch := make(chan model.Event, bufSize)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
	return ch, cancel
}

func (b *Broker) Publish(e model.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			delete(b.subs, ch)
			close(ch)
		}
	}
}

func (b *Broker) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
