package server

/*
#cgo CFLAGS: -g -Wall -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lserver
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "./include/server.h"
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

// Start starts the plugin, satisfying the plugin.Plugin interface. Put any
// start logic here.
func (*serverPlugin) Start(_ coreiface.CoreAPI) error {
	// Call the Rust function
    result := C.start_server()

    defer C.free(unsafe.Pointer(result.data))
    defer C.free(unsafe.Pointer(result.error))

    if result.error != nil {
        fmt.Printf("Go received error: %s\n", C.GoString(result.error))
    }

    // Check for errors from the Rust function
    if result.error != nil {
        return fmt.Errorf(C.GoString(result.error))
    }

    // Print or use the result
    fmt.Println(C.GoString(result.data))

    return nil
}

func (*serverPlugin) Close() error {
	fmt.Println("Goodbye from Server Plugin!")
	return nil
}
