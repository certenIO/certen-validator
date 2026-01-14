// nomocks.go
//
// Anti-mock guardrails for the Accumulate Lite Client.
// This file enforces the mock-free policy of the codebase.

package liteclient

import (
	"fmt"
	"reflect"
	"strings"
)

// NoMocksPolicy enforces that no new mocks are added to the codebase.
// Any type containing "Mock" in its name will trigger a compile-time error
// unless it's in a file with the mock_disabled build tag.
type NoMocksPolicy struct{}

// ValidateType checks if a type name contains "Mock" and panics if found.
// This should be called in init() functions of packages to enforce the policy.
func (NoMocksPolicy) ValidateType(t reflect.Type) {
	typeName := t.Name()
	if strings.Contains(strings.ToLower(typeName), "mock") {
		panic(fmt.Sprintf(
			"Mock type '%s' detected! This codebase is mock-free. "+
				"If this is legacy code, add '//go:build mock_disabled' to the file. "+
				"For new code, use real implementations or test against actual APIs.",
			typeName,
		))
	}
}

// ValidatePackage checks if a package imports any mock libraries.
func (NoMocksPolicy) ValidatePackage(imports []string) {
	mockLibraries := []string{
		"github.com/stretchr/testify/mock",
		"github.com/golang/mock",
		"go.uber.org/mock",
		"github.com/vektra/mockery",
	}

	for _, imp := range imports {
		for _, mockLib := range mockLibraries {
			if strings.Contains(imp, mockLib) {
				panic(fmt.Sprintf(
					"Mock library '%s' imported! This codebase is mock-free. "+
						"Use real implementations or test against actual APIs.",
					imp,
				))
			}
		}
	}
}

// EnforceMockFreePolicy is the global policy enforcer
var EnforceMockFreePolicy = NoMocksPolicy{}