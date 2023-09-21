package handshake

import (
	"fmt"

	coreiface "github.com/ipfs/boxo/coreiface"
	plugin "github.com/ipfs/kubo/plugin"
)

// Plugins is exported list of plugins that will be loaded.
var Plugins = []plugin.Plugin{
	&handshakePlugin{},
}

type handshakePlugin struct{}

var _ plugin.PluginDaemon = (*handshakePlugin)(nil)

// Name returns the plugin's name, satisfying the plugin.Plugin interface.
func (*handshakePlugin) Name() string {
	return "handshake"
}

// Version returns the plugin's version, satisfying the plugin.Plugin interface.
func (*handshakePlugin) Version() string {
	return "0.1.0"
}

// Init initializes plugin, satisfying the plugin.Plugin interface. Put any
// initialization logic here.
func (*handshakePlugin) Init(env *plugin.Environment) error {
	return nil
}

func (*handshakePlugin) Start(_ coreiface.CoreAPI) error {
	fmt.Println("Hello!")
	return nil
}

func (*handshakePlugin) Close() error {
	fmt.Println("Goodbye!")
	return nil
}
