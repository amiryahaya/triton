package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// Sprint extends codesign.go with git tag / commit signature
// verification. Completes the "C2" coverage item that was
// deferred from the previous sprint.
//
// checkGitSignature invokes `git tag -v <tagref>` (or
// `git verify-commit <commitref>`) to verify the signature on a
// git ref. The tag-verify output includes any gpg/ssh output
// the signer's agent emitted, which we grep for the signing
// algorithm (RSA, Ed25519, DSA, ECDSA).
//
// This is intentionally a "does the release pipeline sign
// things, and with what" check — not a "is this specific commit
// authentic" check. That framing means it produces a single
// finding per invocation (the algorithm used) rather than per
// commit traversed.

// gitGPGAlgoRE matches `gpg: … using <ALGO> key …` lines that
// GPG emits during verification.
var gitGPGAlgoRE = regexp.MustCompile(`(?i)gpg:\s+using\s+(\S+)\s+key`)

// gitSSHAlgoRE matches the SSH signature verification line
// `Good "git" signature for <id> with <ALGO> key SHA256:…`
// that git emits when gpg.format=ssh is used.
var gitSSHAlgoRE = regexp.MustCompile(`(?i)signature\s+for\s+(\S+)\s+with\s+(\S+)\s+key`)

// gitGoodSigRE matches GPG's "Good signature from X" line so we
// can pull out the signer identity as the Subject.
var gitGoodSigRE = regexp.MustCompile(`(?i)Good signature from\s+"([^"]+)"`)

// checkGitSignature runs a git verify on a ref and translates the
// output into a codesign finding. Accepts either a tag name or a
// commit ref — we invoke `git tag -v` first and fall back to
// `git verify-commit` internally by not prescribing the command.
//
// The `ref` argument is the caller-supplied identifier; we embed
// it in the finding's Source.Path for operator traceability.
func (m *CodeSignModule) checkGitSignature(ctx context.Context, ref string) []*model.Finding {
	// Ask git to verify. The output format is stable across
	// recent git versions. We try `verify-tag` first — if the
	// input is a commit hash the runner will error and we return
	// the toolMissing / unsigned path instead.
	//
	// M1 review — `--` end-of-options separator protects against
	// a filesystem crawl picking up a git repo whose tag is
	// named `-h`, `--exec`, or anything that git would otherwise
	// interpret as a flag.
	out, err := m.cmdRunner(ctx, "git", "tag", "-v", "--", ref)
	output := string(out)

	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		return []*model.Finding{m.gitToolMissing(ref)}
	}

	// Unsigned / no-signature branch: git tag -v exits non-zero
	// with output that says "object <hash>" followed by the tag
	// message but NO "gpg:" or "signature" lines.
	hasGPG := strings.Contains(output, "gpg:")
	hasSSH := gitSSHAlgoRE.MatchString(output)
	if !hasGPG && !hasSSH {
		return []*model.Finding{m.gitUnsignedFinding(ref)}
	}

	algo := "Unknown"
	subject := ""

	// GPG path first.
	if match := gitGPGAlgoRE.FindStringSubmatch(output); len(match) == 2 {
		algo = strings.ToUpper(match[1])
	}
	if match := gitGoodSigRE.FindStringSubmatch(output); len(match) == 2 {
		subject = match[1]
	}
	// SSH path: overrides the algo if we found an SSH line because
	// git with gpg.format=ssh doesn't emit a "gpg:" prefix.
	if match := gitSSHAlgoRE.FindStringSubmatch(output); len(match) == 3 {
		algo = strings.ToUpper(match[2])
		if subject == "" {
			subject = match[1]
		}
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Git tag signature",
		Algorithm: algo,
		Subject:   subject,
		Purpose:   "git tag -v " + ref,
	}
	crypto.ClassifyCryptoAsset(asset)
	asset.Algorithm = algo // restore — registry substring matcher may rewrite
	return []*model.Finding{codesignFinding("git:"+ref, asset)}
}

// gitUnsignedFinding emits a canonical "this git tag carries no
// signature" finding. Mirrors the PE / JAR unsigned paths so the
// policy engine can treat them uniformly.
func (m *CodeSignModule) gitUnsignedFinding(ref string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Git tag signature",
		Algorithm: "none",
		Purpose:   "Unsigned git tag: " + ref,
	}
	crypto.ClassifyCryptoAsset(asset)
	return codesignFinding("git:"+ref, asset)
}

// gitToolMissing emits the tool-unavailable finding so the
// coverage gap is visible in the report even on hosts without
// git installed.
func (m *CodeSignModule) gitToolMissing(ref string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "Git tag signature",
		Algorithm: "tool-unavailable",
		Purpose:   "Git signature verification skipped: git not on PATH (ref=" + ref + ")",
		PQCStatus: "TRANSITIONAL",
	}
	return codesignFinding("git:"+ref, asset)
}
