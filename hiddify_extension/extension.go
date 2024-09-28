package hiddify_extension

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hiddify/hiddify-core/common"
	"github.com/hiddify/hiddify-core/config"
	ex "github.com/hiddify/hiddify-core/extension"
	"github.com/hiddify/hiddify-core/extension/sdk"
	ui "github.com/hiddify/hiddify-core/extension/ui"

	"github.com/hiddify/hiddify-ip-scanner-extension/cleanip_scanner"
	v2 "github.com/hiddify/hiddify-core/v2"

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
		e.UpdateUI(e.buildForm())
	}()

	e.result = green.Sprintf("Scanning...\n")
	e.resultTbl.SetRows([][]string{})
	// new scanner
	scanner := cleanip_scanner.NewScannerEngine(&cleanip_scanner.ScannerOptions{
		UseIPv4:         true,
		UseIPv6:         common.CanConnectIPv6(),
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

			e.resultTbl.AddRow(ipinfo.AddrPort.Addr(), e.formatPing(ipinfo, err))
			e.UpdateUI(e.buildForm())
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
			e.resultTbl.SetRows([][]string{})

			for _, info := range ipList {
				e.resultTbl.AddRow(info.AddrPort.Addr(), e.formatPing(info, nil))
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

func (e *CleanIPExtension) formatPing(info cleanip_scanner.IPInfo, err error) string {
	if err != nil {
		return red.Sprint(err)
	}

	rtt := info.RTT.Milliseconds()
	switch {
	case rtt <= 0:
		return red.Sprint("-")
	case rtt > 3000:
		return red.Sprint(rtt, "ms")
	case rtt > 500:
		return yellow.Sprint(rtt, "ms")
	default:
		return green.Sprint(rtt, "ms")
	}
}

func (e *CleanIPExtension) SubmitData(data map[string]string) error {
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
}

func (e *CleanIPExtension) Cancel() error {
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.isRunning = false
	return nil
}

func (e *CleanIPExtension) Stop() error {
	return e.Cancel()
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

func (e *CleanIPExtension) buildForm() ui.Form {
	var sb strings.Builder
	e.resultTbl.WithWriter(&sb).Print()
	if e.isRunning {
		return ui.Form{
			Title:       "Clean IP Extension",
			Description: "Running...",
			Buttons:     []string{ui.Button_Cancel},
			Fields: []ui.FormField{
				{
					Type:     ui.FieldConsole,
					Readonly: true,
					Key:      resultKey,
					Label:    "Result",
					Value:    e.result + sb.String(),
					Lines:    20,
				},
			},
		}
	} else {
		configStr := ""
		if e.Base.Data.Config != nil {
			configBytes, err := json.MarshalIndent(e.Base.Data.Config, "", " ")
			if err != nil {
				configStr = err.Error()
			} else {
				configStr = string(configBytes)
			}
		}
		return ui.Form{
			Title:       "Clean IP Extension",
			Description: "For finding clean IP",
			Buttons:     []string{ui.Button_Submit},
			Fields: []ui.FormField{
				{
					Type:        ui.FieldTextArea,
					Key:         configKey, // TODO use e.Base.ValName(&e.Base.Data.Config)
					Label:       "Config",
					Placeholder: "vless://xxxxxx",
					Required:    true,
					Value:       configStr,
					Readonly:    e.isRunning,
				},
				{
					Type:        ui.FieldTextArea,
					Key:         iprangesKey,
					Label:       "IP Range",
					Placeholder: "1.1.1.0/24\n2.1.1.0/24\n3.1.1.0/24",
					Required:    true,
					Value:       e.getIpRangeStr(),
					Readonly:    e.isRunning,
				},
				{
					Type:        ui.FieldInput,
					Key:         countKey,
					Label:       "Count",
					Placeholder: "This will be the count",
					Required:    true,
					Value:       fmt.Sprintf("%d", e.Base.Data.Count),
					Validator:   ui.ValidatorDigitsOnly,
					Readonly:    e.isRunning,
				},
				{
					Type:     ui.FieldSwitch,
					Key:      useXrayWhenPossibleKey,
					Label:    "Use Xray when possible",
					Value:    strconv.FormatBool(e.Base.Data.UseXrayWhenPossible),
					Readonly: e.isRunning,
				},
				{
					Type:     ui.FieldConsole,
					Readonly: true,
					Key:      resultKey,
					Label:    "Result",
					Value:    e.result + sb.String(),
					Lines:    10,
				},
			},
		}
	}
}

func (e *CleanIPExtension) getIpRangeStr() string {
	res := ""
	for _, ip := range e.Base.Data.SearchIPRanges {
		res = res + fmt.Sprintf("%s\n", ip.String())
	}
	return res
}

func (e *CleanIPExtension) setFormData(data map[string]string) error {
	if val, ok := data[countKey]; ok {
		if intValue, err := strconv.Atoi(val); err == nil {
			e.Base.Data.Count = intValue
		} else {
			// return err
		}
	}
	if val, ok := data[iprangesKey]; ok {
		e.Base.Data.SearchIPRanges = make([]netip.Prefix, 0)
		for _, ip := range strings.Split(val, "\n") {
			if strings.TrimSpace(ip) == "" {
				continue
			}

			if prefix, err := netip.ParsePrefix(strings.TrimSpace(ip)); err == nil {
				e.Base.Data.SearchIPRanges = append(e.Base.Data.SearchIPRanges, prefix)
			} else {
				return err
			}
		}
	}

	if val, ok := data[useXrayWhenPossibleKey]; ok {
		if selectedValue, err := strconv.ParseBool(val); err == nil {
			e.Base.Data.UseXrayWhenPossible = selectedValue
		} else {
			return err
		}
	}

	if val, ok := data[configKey]; ok {
		singConfig, err := sdk.ParseConfig(nil, val)
		if err != nil {
			return err
		}
		e.Base.Data.Config = singConfig
	}
	return nil
}

func (e *CleanIPExtension) GetUI() ui.Form {
	return e.buildForm()
}

func init() {
	ex.RegisterExtension(
		ex.ExtensionFactory{
			Id:          "github.com/hiddify/example_extension/cleanip_extension",
			Title:       "Clean IP Extension",
			Description: "For Finding clean IP",
			Builder:     NewCleanIPExtension,
		})
}
