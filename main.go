package main

import (
	_ "github.com/hiddify/hiddify-ip-scanner-extension/hiddify_extension"

	"github.com/hiddify/hiddify-core/cmd"
)

func main() {
	cmd.StartExtension()
}
