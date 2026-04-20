package manageserver

import "github.com/amiryahaya/triton/pkg/manageserver/agents"

// SetAgentCapGuardForTest swaps the agent-cap guard on the agents
// admin handler. Used by Batch H integration tests that assert the
// hard-cap enforcement path on POST /api/v1/admin/enrol/agent.
//
// Production code never calls this. Pair with
// ClearSeatCapGuardForTest in t.Cleanup. Handlers observe the change
// on their next request because they consult the GuardProvider
// closure — which reads s.agentCapGuardOverride under s.mu — per call.
func SetAgentCapGuardForTest(s *Server, g agents.AgentCapGuard) {
	s.mu.Lock()
	s.agentCapGuardOverride = g
	s.mu.Unlock()
}
