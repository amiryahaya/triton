package cmd

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAgentControlState_PauseRespected(t *testing.T) {
	st := &agentControlState{}
	st.setPausedUntil(time.Now().Add(1 * time.Hour))

	until, paused := st.pauseDeadline()
	assert.True(t, paused)
	assert.True(t, until.After(time.Now()))
}

func TestAgentControlState_PastPausedUntilNotPaused(t *testing.T) {
	st := &agentControlState{}
	st.setPausedUntil(time.Now().Add(-1 * time.Hour))

	_, paused := st.pauseDeadline()
	assert.False(t, paused, "past paused_until should mean not paused")
}

func TestAgentControlState_ZeroNotPaused(t *testing.T) {
	st := &agentControlState{}
	_, paused := st.pauseDeadline()
	assert.False(t, paused)
}

func TestAgentControlState_ScanCancelCalled(t *testing.T) {
	st := &agentControlState{}
	var called int
	var mu sync.Mutex
	st.setScanCancel(func() {
		mu.Lock()
		called++
		mu.Unlock()
	})
	st.cancelScan()
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, called)
}

func TestAgentControlState_CancelNoScanNoop(t *testing.T) {
	st := &agentControlState{}
	// No panic when no scan is in flight.
	assert.NotPanics(t, func() {
		st.cancelScan()
	})
}

func TestAgentControlState_SetClearScanCancel(t *testing.T) {
	st := &agentControlState{}
	_, cancel := context.WithCancel(context.Background())
	st.setScanCancel(cancel)
	st.setScanCancel(nil) // clear on scan end
	// cancelScan should now be a no-op (fn is nil).
	assert.NotPanics(t, func() {
		st.cancelScan()
	})
}

func TestForceRunArgsRoundTrip(t *testing.T) {
	args := map[string]string{"profile": "quick"}
	buf, _ := json.Marshal(args)
	var decoded map[string]string
	assert.NoError(t, json.Unmarshal(buf, &decoded))
	assert.Equal(t, "quick", decoded["profile"])
}
