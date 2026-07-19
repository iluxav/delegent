package store_test

import (
	"testing"

	"delegent.dev/gateway/store"
	"delegent.dev/gateway/store/storetest"
)

func TestMemStore_Conformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return store.NewMemStore() })
}
