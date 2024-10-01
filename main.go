package main

import (
	"github.com/hiddify/hiddify-core/extension/server"
	_ "github.com/hiddify/hiddify-ip-scanner-extension/hiddify_extension"
)

func main() {
	server.StartTestExtensionServer()

}
