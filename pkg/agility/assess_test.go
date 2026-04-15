package agility

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestAssessAll_EmptyInput(t *testing.T) {
	if got := AssessAll(nil); got != nil {
		t.Errorf("AssessAll(nil) = %v, want nil", got)
	}
	if got := AssessAll(&model.ScanResult{}); got != nil {
		t.Errorf("AssessAll(empty) = %v, want nil", got)
	}
}
