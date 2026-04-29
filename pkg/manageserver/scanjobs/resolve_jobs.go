package scanjobs

// ResolveJobs expands (hosts × jobTypes) into job rows to create and skipped
// pairs. It is a pure function with no DB access.
//
// Rules (per spec):
//   - port_survey: always created, no credential needed.
//   - filesystem + enrolled agent (ConnectionType="agent"): create, no cred.
//   - filesystem + SSH (CredentialsRef + SSHPort set): create with cred.
//   - filesystem + neither: skip with reason "no_credential".
//   - When a host has both agent and SSH cred, agent wins (cred ignored).
func ResolveJobs(hosts []ResolveHostInfo, jobTypes []JobType) (toCreate []JobSpec, skipped []SkippedJob) {
	for _, h := range hosts {
		for _, jt := range jobTypes {
			switch jt {
			case JobTypePortSurvey:
				toCreate = append(toCreate, JobSpec{HostID: h.ID, JobType: jt})
			case JobTypeFilesystem:
				if h.ConnectionType == "agent" {
					toCreate = append(toCreate, JobSpec{HostID: h.ID, JobType: jt})
				} else if h.CredentialsRef != nil && h.SSHPort > 0 {
					sshPort := h.SSHPort
					toCreate = append(toCreate, JobSpec{
						HostID:         h.ID,
						JobType:        jt,
						CredentialsRef: h.CredentialsRef,
						SSHPort:        &sshPort,
					})
				} else {
					skipped = append(skipped, SkippedJob{
						HostID:  h.ID,
						JobType: jt,
						Reason:  "no_credential",
					})
				}
			}
		}
	}
	return
}
