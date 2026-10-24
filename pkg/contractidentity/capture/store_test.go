// Copyright 2026 Certen Protocol

package capture_test

import (
	"testing"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/contractidentity/capture/storetest"
)

func TestMemStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) capture.Store { return capture.NewMemStore() })
}
