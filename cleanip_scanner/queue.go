package cleanip_scanner

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

type IPQueue struct {
	queue        []IPInfo
	maxQueueSize int
	mu           sync.Mutex
	available    chan struct{}
	maxTTL       time.Duration
	rttThreshold time.Duration
	inIdealMode  bool
	log          *slog.Logger
	reserved     IPInfQueue
}

func NewIPQueue(opts *ScannerOptions) *IPQueue {
	var reserved IPInfQueue
	return &IPQueue{
		queue:        make([]IPInfo, 0),
		maxQueueSize: opts.IPQueueSize,
		maxTTL:       opts.IPQueueTTL,
		rttThreshold: opts.MaxDesirableRTT,
		available:    make(chan struct{}, opts.IPQueueSize),
		log:          opts.Logger.With(slog.String("subsystem", "engine/queue")),
		reserved:     reserved,
	}
}

func (q *IPQueue) Enqueue(info IPInfo) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	defer func() {
		q.log.Debug("queue change", "len", len(q.queue))
		for _, ipInfo := range q.queue {
			q.log.Debug(
				"queue change",
				"created", ipInfo.CreatedAt,
				"addr", ipInfo.AddrPort,
				"rtt", ipInfo.RTT,
			)
		}
	}()

	q.log.Debug("Enqueue: Sorting queue by RTT")
	sort.Slice(q.queue, func(i, j int) bool {
		return q.queue[i].RTT < q.queue[j].RTT
	})

	if len(q.queue) == 0 {
		q.log.Debug("Enqueue: empty queue adding first available item")
		q.queue = append(q.queue, info)
		return false
	}

	if info.RTT <= q.rttThreshold {
		q.log.Debug("Enqueue: the new item's RTT is less than at least one of the members.")
		if len(q.queue) >= q.maxQueueSize && info.RTT < q.queue[len(q.queue)-1].RTT {
			q.log.Debug("Enqueue: the queue is full, remove the item with the highest RTT.")
			q.queue = q.queue[:len(q.queue)-1]
		} else if len(q.queue) < q.maxQueueSize {
			q.log.Debug("Enqueue: Insert the new item in a sorted position.")
			index := sort.Search(len(q.queue), func(i int) bool { return q.queue[i].RTT > info.RTT })
			q.queue = append(q.queue[:index], append([]IPInfo{info}, q.queue[index:]...)...)
		} else {
			q.log.Debug("Enqueue: The Queue is full but we keep the new item in the reserved queue.")
			q.reserved.Enqueue(info)
		}
	}

	q.log.Debug("Enqueue: Checking if any member has a higher RTT than the threshold.")
	for _, member := range q.queue {
		if member.RTT > q.rttThreshold {
			return false // If any member has a higher RTT than the threshold, return false.
		}
	}

	q.log.Debug("Enqueue: All members have an RTT lower than the threshold.")
	if len(q.queue) < q.maxQueueSize {
		// the queue isn't full dont wait
		return false
	}

	q.inIdealMode = true
	// ok wait for expiration signal
	q.log.Debug("Enqueue: All members have an RTT lower than the threshold. Waiting for expiration signal.")
	return true
}

func (q *IPQueue) Dequeue() (IPInfo, bool) {
	defer func() {
		q.log.Debug("queue change", "len", len(q.queue))
		for _, ipInfo := range q.queue {
			q.log.Debug(
				"queue change",
				"created", ipInfo.CreatedAt,
				"addr", ipInfo.AddrPort,
				"rtt", ipInfo.RTT,
			)
		}
	}()
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		return IPInfo{}, false
	}

	info := q.queue[len(q.queue)-1]
	q.queue = q.queue[0 : len(q.queue)-1]

	q.available <- struct{}{}

	return info, true
}

func (q *IPQueue) Expire() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.inIdealMode {
		q.log.Debug("Expire: Not in ideal mode")
		q.available <- struct{}{}
		return
	}

	q.log.Debug("Expire: In ideal mode")
	defer func() {
		q.log.Debug("queue change", "len", len(q.queue))
		for _, ipInfo := range q.queue {
			q.log.Debug(
				"queue change",
				"created", ipInfo.CreatedAt,
				"addr", ipInfo.AddrPort,
				"rtt", ipInfo.RTT,
			)
		}
	}()

	shouldStartNewScan := false
	resQ := make([]IPInfo, 0)
	for i := 0; i < len(q.queue); i++ {
		if time.Since(q.queue[i].CreatedAt) > q.maxTTL {
			q.log.Debug("Expire: Removing expired item from queue")
			shouldStartNewScan = true
		} else {
			resQ = append(resQ, q.queue[i])
		}
	}
	q.queue = resQ
	q.log.Debug("Expire: Adding reserved items to queue")
	for i := 0; i < q.maxQueueSize && i < q.reserved.Size(); i++ {
		q.queue = append(q.queue, q.reserved.Dequeue())
	}
	if shouldStartNewScan {
		q.available <- struct{}{}
	}
}

func (q *IPQueue) AvailableIPs(desc bool) []IPInfo {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Create a separate slice for sorting
	sortedQueue := make([]IPInfo, len(q.queue))
	copy(sortedQueue, q.queue)

	// Sort by RTT ascending/descending
	sort.Slice(sortedQueue, func(i, j int) bool {
		if desc {
			return sortedQueue[i].RTT > sortedQueue[j].RTT
		}
		return sortedQueue[i].RTT < sortedQueue[j].RTT
	})

	return sortedQueue
}
