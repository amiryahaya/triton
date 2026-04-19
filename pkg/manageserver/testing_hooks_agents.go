package manageserver

import "github.com/amiryahaya/triton/pkg/manageserver/agents"

// SetAgentCapGuardForTest swaps the agent-cap guard on the agents
// admin handler. Used by Batch H integration tests that assert the
// hard-cap enforcement path on POST /api/v1/admin/enrol/agent.
//
// Production code never calls this. Pair with
// ClearSeatCapGuardForTest in t.Cleanup.
func SetAgentCapGuardForTest(s *Server, g agents.AgentCapGuard) {
	s.mu.Lock()
	s.agentCapGuardOverride = g
	if s.agentsAdmin != nil {
		s.agentsAdmin.Guard = g
	}
	s.mu.Unlock()
}
