package cleanip_scanner

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/batch"
)

type Engine struct {
	generator  *IpGenerator
	ipQueue    *IPQueue
	ping       func(netip.Addr) (IPInfo, error)
	log        *slog.Logger
	concurrent int
}

func NewScannerEngine(opts *ScannerOptions) *Engine {
	opts.Logger = slog.With(slog.String("ipscanner", "scanner"))
	queue := NewIPQueue(opts)

	return &Engine{
		ipQueue:    queue,
		ping:       opts.PingFunc,
		generator:  NewIterator(opts),
		log:        opts.Logger.With(slog.String("subsystem", "scanner/engine")),
		concurrent: opts.ConcurrentPings,
	}
}

func (e *Engine) GetAvailableIPs(desc bool) []IPInfo {
	if e.ipQueue != nil {
		return e.ipQueue.AvailableIPs(desc)
	}
	return nil
}

func (e *Engine) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.ipQueue.available:
			e.log.Debug("Started new scanning round")
			batchIps, err := e.generator.NextBatch()
			if err != nil {
				e.log.Error("Error while generating IP: %v", err)
				// in case of disastrous error, to prevent resource draining wait for 2 seconds and try again
				time.Sleep(2 * time.Second)
				continue
			}
			b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](e.concurrent))

			for _, ip := range batchIps {
				realIP := ip
				b.Go(realIP.String(), func() (any, error) {
					select {
					case <-ctx.Done():
						break
					default:
						e.log.Debug("pinging IP", "addr", ip)
						if ipInfo, err := e.ping(ip); err == nil {
							e.log.Debug("ping success", "addr", ipInfo.AddrPort, "rtt", ipInfo.RTT)
							e.ipQueue.Enqueue(ipInfo)
						} else {
							e.log.Error("ping error", "addr", ip, "error", err)
						}

					}
					return nil, nil
				})
			}
			b.Wait()
		default:
			e.log.Debug("calling expire")
			e.ipQueue.Expire()
			time.Sleep(200 * time.Millisecond)
		}
	}
}
