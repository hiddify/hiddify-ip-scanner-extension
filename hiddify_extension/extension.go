package hiddify_extension

import (
	"context"

	"fmt"
	"net/netip"
	"sync"
	"time"

	ui "github.com/hiddify/hiddify-core/extension/ui"

	"github.com/hiddify/hiddify-core/config"
	ex "github.com/hiddify/hiddify-core/extension"

	v2 "github.com/hiddify/hiddify-core/v2"
	"github.com/hiddify/hiddify-ip-scanner-extension/cleanip_scanner"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/sagernet/sing-box/option"
)

// Field name constants
const (
	configKey              = "configKey"
	iprangesKey            = "iprangesKey"
	useXrayWhenPossibleKey = "useXrayWhenPossibleKey"
	countKey               = "countKey"
	resultKey              = "resultKey"
)

var (
	red    = color.New(color.FgRed).Add(color.Bold)
	blue   = color.New(color.FgBlue)
	green  = color.New(color.FgGreen).Add(color.Underline)
	yellow = color.New(color.FgYellow).Add(color.Bold)
)

type CleanIPExtensionConfig struct {
	Count               int                      `json:"count"`
	SearchIPRanges      []netip.Prefix           `json:"searchIPranges"`
	UseXrayWhenPossible bool                     `json:"useXrayWhenPossible"`
	Config              *option.Options          `json:"config,omitempty"`
	CleanIPList         []cleanip_scanner.IPInfo `json:"cleanIPList"`
}

type CleanIPExtension struct {
	ex.Base[CleanIPExtensionConfig]
	cancel    context.CancelFunc
	result    string
	isRunning bool
	resultTbl table.Table
	tblMutex  sync.Mutex
}

func NewCleanIPExtension() ex.Extension {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()
	tbl := table.New("Address", "RTT (ping)")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)
	return &CleanIPExtension{
		Base: ex.Base[CleanIPExtensionConfig]{
			Data: CleanIPExtensionConfig{
				Count:               10,
				SearchIPRanges:      cleanip_scanner.DefaultCFRanges(),
				UseXrayWhenPossible: false,
				Config:              nil,
				CleanIPList:         make([]cleanip_scanner.IPInfo, 0),
			},
		},
		isRunning: false,
		result:    fmt.Sprint("Please enter your ", red.Sprintf("config"), " and at least one ", blue.Sprintf("IP range"), "!\n"),
		resultTbl: tbl,
	}
}

func (e *CleanIPExtension) Ping(ip netip.Addr) (cleanip_scanner.IPInfo, error) {
	config := e.Base.Data.Config
	for _, outbound := range config.Outbounds {
		outbound.VLESSOptions.Server = ip.String()
		outbound.VMessOptions.Server = ip.String()
		outbound.TrojanOptions.Server = ip.String()
		outbound.WireGuardOptions.Server = ip.String()
	}
	instance, err := v2.RunInstance(nil, config)
	if err != nil {
		return cleanip_scanner.IPInfo{
			AddrPort:  netip.AddrPortFrom(ip, 0),
			RTT:       -1,
			CreatedAt: time.Now(),
		}, err
	}
	instance.PingCloudflare() // wait for first ping
	ping, err := instance.PingCloudflare()

	return cleanip_scanner.IPInfo{
		AddrPort:  netip.AddrPortFrom(ip, 80),
		RTT:       ping,
		CreatedAt: time.Now(),
	}, err
}

func (e *CleanIPExtension) RunScan(ctx context.Context) {
	e.isRunning = true
	defer func() {
		e.isRunning = false
		e.UpdateUI(e.GetUI())
	}()

	e.result = green.Sprintf("Scanning...\n")
	e.tableClean()
	// new scanner
	scanner := cleanip_scanner.NewScannerEngine(&cleanip_scanner.ScannerOptions{
		UseIPv4:         true,
		UseIPv6:         false,
		MaxDesirableRTT: 500 * time.Millisecond,
		IPQueueSize:     100,
		IPQueueTTL:      10 * time.Second,
		ConcurrentPings: 10,

		// MaxDesirableIPs: e.Base.Data.Count,
		CidrList: e.Base.Data.SearchIPRanges,
		PingFunc: func(ip netip.Addr) (cleanip_scanner.IPInfo, error) {
			select {
			case <-ctx.Done(): // if cancel is called
				return cleanip_scanner.IPInfo{
					AddrPort:  netip.AddrPortFrom(ip, 0),
					RTT:       -1,
					CreatedAt: time.Now(),
				}, fmt.Errorf("ctx.Done")
			default:
			}
			ipinfo, err := e.Ping(ip)

			e.addRow(ipinfo.AddrPort.Addr(), e.formatPing(ipinfo, err))
			e.UpdateUI(e.GetUI())
			return ipinfo, err
		},
	},
	)

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	scanner.Run(ctx)

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	for {
		ipList := scanner.GetAvailableIPs(false)
		if len(ipList) > 1 {
			e.Base.Data.CleanIPList = ipList
			e.result = yellow.Sprintf("Final Result:\n")
			// for i := 0; i < e.Base.Data.Count; i++ {
			// 	// result = append(result, ipList[i])
			// 	e.result = fmt.Sprintln(e.result, ipList[i].AddrPort.Addr(), " : ", ipList[i].RTT.Milliseconds())
			// }
			e.tableClean()

			for _, info := range ipList {
				e.addRow(info.AddrPort.Addr(), e.formatPing(info, nil))
				// e.result = fmt.Sprintln(e.result, ipList[i].AddrPort.Addr(), " : ", ipList[i].RTT.Milliseconds())
			}

		}

		select {
		case <-ctx.Done():
			// Context is done
			return
		case <-t.C:
			// Prevent the loop from spinning too fast
			continue
		}
	}
}

func (e *CleanIPExtension) SubmitData(button string, data map[string]string) error {
	switch button {
	case ui.ButtonDialogOk, ui.ButtonDialogClose:
		return nil
	case ui.ButtonCancel:
		return e.stop()
	case ui.ButtonSubmit:
		err := e.setFormData(data)
		if err != nil {
			e.ShowMessage("Invalid data", err.Error())
			return err
		}
		if e.cancel != nil {
			e.cancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		e.cancel = cancel

		go e.RunScan(ctx)

		return nil

	default:
		// Show message for undefined button actions
		return e.ShowMessage("Button "+button+" is pressed", "No action is defined for this button")
	}

}

func (e *CleanIPExtension) stop() error {
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.isRunning = false
	return nil
}

func (e *CleanIPExtension) Close() error {
	return e.stop()
}

func (e *CleanIPExtension) modifyIP(outbound option.Outbound, ip netip.Addr) {
	// TODO: base on config Type
	outbound.VLESSOptions.Server = ip.String()
	outbound.VMessOptions.Server = ip.String()
	outbound.TrojanOptions.Server = ip.String()
	outbound.WireGuardOptions.Server = ip.String()
}

func (e *CleanIPExtension) BeforeAppConnect(hiddifySettings *config.HiddifyOptions, singconfig *option.Options) error {
	if len(e.Base.Data.CleanIPList) == 0 {
		return nil
	}
	for i, outbound := range singconfig.Outbounds {
		ip := e.Base.Data.CleanIPList[i%len(e.Base.Data.CleanIPList)].AddrPort.Addr()
		e.modifyIP(outbound, ip)
	}

	return nil
}

func init() {
	ex.RegisterExtension(
		ex.ExtensionFactory{
			Id:          "github.com/hiddify/hiddify-ip-scanner-extension/hiddify_extension",
			Title:       "Clean IP Extension",
			Description: "For Finding clean IP",
			Builder:     NewCleanIPExtension,
		})
}
