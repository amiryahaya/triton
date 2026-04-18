//go:build windows

package jobrunner

import "os"

// signalZero on windows. We use os.Interrupt here but realPIDAlive
// short-circuits on FindProcess error before the Signal call, so this
// value is effectively unused on windows builds.
var signalZero = os.Interrupt
