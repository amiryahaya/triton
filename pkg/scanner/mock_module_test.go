package scanner

import (
	"context"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// MockModule is a configurable mock implementing the Module interface for tests.
type MockModule struct {
	name       string
	category   model.ModuleCategory
	targetType model.ScanTargetType
	findings   []*model.Finding
	scanDelay  time.Duration
	scanErr    error
}

func (m *MockModule) Name() string                         { return m.name }
func (m *MockModule) Category() model.ModuleCategory       { return m.category }
func (m *MockModule) ScanTargetType() model.ScanTargetType { return m.targetType }

func (m *MockModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if m.scanDelay > 0 {
		select {
		case <-time.After(m.scanDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.scanErr != nil {
		return m.scanErr
	}

	for _, f := range m.findings {
		select {
		case findings <- f:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
