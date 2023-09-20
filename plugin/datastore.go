package plugin

import (
	"github.com/jmfrank63/kubo/repo/fsrepo"
)

// PluginDatastore is an interface that can be implemented to add handlers for
// for different datastores.
type PluginDatastore interface {
	Plugin

	DatastoreTypeName() string
	DatastoreConfigParser() fsrepo.ConfigFromMap
}
