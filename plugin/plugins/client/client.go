package client

/*
#cgo LDFLAGS: -L. -lclient
#include <stdlib.h>

typedef struct {
	char* data;
	char* error;
} Result;

extern Result start_client();
*/
import "C"

import (
	"fmt"
	"unsafe"

	coreiface "github.com/ipfs/boxo/coreiface"
	plugin "github.com/ipfs/kubo/plugin"
)

// Plugins is exported list of plugins that will be loaded.
var Plugins = []plugin.Plugin{
	&clientPlugin{},
}

type clientPlugin struct{}

var _ plugin.PluginDaemon = (*clientPlugin)(nil)

// Name returns the plugin's name, satisfying the plugin.Plugin interface.
func (*clientPlugin) Name() string {
	return "client"
}

// Version returns the plugin's version, satisfying the plugin.Plugin interface.
func (*clientPlugin) Version() string {
	return "0.1.0"
}

// Init initializes plugin, satisfying the plugin.Plugin interface. Put any
// initialization logic here.
func (*clientPlugin) Init(env *plugin.Environment) error {
	return nil
}

func (*clientPlugin) Start(_ coreiface.CoreAPI) error {
	fmt.Println("Hello from Client via Rust!")

	// Call the Rust function
	result := C.start_client()
	defer C.free(unsafe.Pointer(result.data))
	defer C.free(unsafe.Pointer(result.error))

	// Check for errors from the Rust function
	if result.error != nil {
		return fmt.Errorf(C.GoString(result.error))
	}

	// Print or use the result
	fmt.Println(C.GoString(result.data))

	return nil
}

func (*clientPlugin) Close() error {
	fmt.Println("Goodbye from Client!")
	return nil
}
