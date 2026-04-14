package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
)

func TestJavaBytecodeModule_RegisteredInDefaults(t *testing.T) {
	cfg := &scannerconfig.Config{Profile: "comprehensive"}
	e := New(cfg)
	e.RegisterDefaultModules()
	found := false
	for _, m := range e.modules {
		if m.Name() == "java_bytecode" {
			found = true
			break
		}
	}
	if !found {
		t.Error("java_bytecode not registered by RegisterDefaultModules")
	}
}
