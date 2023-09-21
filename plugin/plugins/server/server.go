package server

import (
	"fmt"

	coreiface "github.com/ipfs/boxo/coreiface"
	plugin "github.com/ipfs/kubo/plugin"
)

// Plugins is exported list of plugins that will be loaded.
var Plugins = []plugin.Plugin{
	&serverPlugin{},
}

type serverPlugin struct{}

var _ plugin.PluginDaemon = (*serverPlugin)(nil)

// Name returns the plugin's name, satisfying the plugin.Plugin interface.
func (*serverPlugin) Name() string {
	return "server"
}

// Version returns the plugin's version, satisfying the plugin.Plugin interface.
func (*serverPlugin) Version() string {
	return "0.1.0"
}

// Init initializes plugin, satisfying the plugin.Plugin interface. Put any
// initialization logic here.
func (*serverPlugin) Init(env *plugin.Environment) error {
	return nil
}

func (*serverPlugin) Start(_ coreiface.CoreAPI) error {
	fmt.Println("Hello from Server!")
	return nil
}

func (*serverPlugin) Close() error {
	fmt.Println("Goodbye from Server!")
	return nil
}
