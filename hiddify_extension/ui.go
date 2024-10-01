package hiddify_extension

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hiddify/hiddify-core/extension/sdk"
	ui "github.com/hiddify/hiddify-core/extension/ui"
	"github.com/hiddify/hiddify-ip-scanner-extension/cleanip_scanner"
)

func (e *CleanIPExtension) GetUI() ui.Form {
	if e.isRunning {
		return e.getRunningUI()
	} else {
		return e.getStoppedUI()
	}
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

func (e *CleanIPExtension) getRunningUI() ui.Form {
	return ui.Form{
		Title:       "Clean IP Extension",
		Description: "Running...",
		Fields: [][]ui.FormField{
			{{
				Type:     ui.FieldConsole,
				Readonly: true,
				Key:      resultKey,
				Label:    "Result",
				Value:    e.result + e.tableString(),
				Lines:    20,
			}},
			{{Type: ui.FieldButton, Key: ui.ButtonCancel, Label: "Cancel"}},
		},
	}
}
func (e *CleanIPExtension) getStoppedUI() ui.Form {
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
		Fields: [][]ui.FormField{
			{{
				Type:        ui.FieldTextArea,
				Key:         configKey, // TODO use e.Base.ValName(&e.Base.Data.Config)
				Label:       "Config",
				Placeholder: "vless://xxxxxx",
				Required:    true,
				Value:       configStr,
				Readonly:    e.isRunning,
			}},
			{{
				Type:        ui.FieldTextArea,
				Key:         iprangesKey,
				Label:       "IP Range",
				Placeholder: "1.1.1.0/24\n2.1.1.0/24\n3.1.1.0/24",
				Required:    true,
				Value:       e.getIpRangeStr(),
				Readonly:    e.isRunning,
			}},
			{{
				Type:        ui.FieldInput,
				Key:         countKey,
				Label:       "Count",
				Placeholder: "This will be the count",
				Required:    true,
				Value:       fmt.Sprintf("%d", e.Base.Data.Count),
				Validator:   ui.ValidatorDigitsOnly,
				Readonly:    e.isRunning,
			}},
			{{
				Type:     ui.FieldSwitch,
				Key:      useXrayWhenPossibleKey,
				Label:    "Use Xray when possible",
				Value:    strconv.FormatBool(e.Base.Data.UseXrayWhenPossible),
				Readonly: e.isRunning,
			}},
			{{
				Type:     ui.FieldConsole,
				Readonly: true,
				Key:      resultKey,
				Label:    "Result",
				Value:    e.result + e.tableString(),
				Lines:    10,
			}},
			{{Type: ui.FieldButton, Key: ui.ButtonSubmit, Label: "Submit"}},
		},
	}
}

func (e *CleanIPExtension) getIpRangeStr() string {
	res := ""
	for _, ip := range e.Base.Data.SearchIPRanges {
		res = res + fmt.Sprintf("%s\n", ip.String())
	}
	return res
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
