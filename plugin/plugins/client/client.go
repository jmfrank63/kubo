package client

/*
#cgo CFLAGS: -g -Wall -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lclient
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "./include/client.h"
*/
import "C"

import (
	"context"
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

// Start starts the plugin, satisfying the plugin.Plugin interface. Put any
// start logic here.
func (*clientPlugin) Start(api coreiface.CoreAPI) error {

    // Get the local peer ID
    peerID, err := getLocalPeerID(api)
    if err != nil {
        return err
    }

    cPeerID := C.CString(peerID)
    defer C.free(unsafe.Pointer(cPeerID)) // Release memory

    // Call the Rust function
    result := C.start_client(cPeerID)

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

func (*clientPlugin) Close() error {
	fmt.Println("Goodbye from Client Plugin!")
    C.close_client()
	return nil
}

func getLocalPeerID(api coreiface.CoreAPI) (string, error) {
    // Get swarm API from the CoreAPI
    keyAPI := api.Key()

    // Use the swarm API to get a list of peers we are connected to
    key, err := keyAPI.Self(context.Background())
    if err != nil {
        return "", err
    }

    keys, err := keyAPI.List(context.Background())
    if err != nil {
        return "", err
    }

    for _, key := range keys {
        fmt.Printf("Key: %s\n", key.Name())
    }

    peerID := key.ID().Pretty()
    // Return the peer ID of the first peer, assuming it's our node's ID
    return peerID, nil
}
