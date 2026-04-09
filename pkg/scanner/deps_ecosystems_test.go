package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*DepsEcosystemsModule)(nil)

func TestDepsEcosystemsModule_Interface(t *testing.T) {
	t.Parallel()
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	assert.Equal(t, "deps_ecosystems", m.Name())
	assert.Equal(t, model.CategoryPassiveFile, m.Category())
	assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

// --- Matcher ---

func TestIsDepsEcosystemFile(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		// Python
		"/srv/app/requirements.txt": true,
		"/srv/app/pyproject.toml":   true,
		"/srv/app/Pipfile.lock":     true,
		"/srv/app/poetry.lock":      true,
		// Node
		"/srv/app/package.json":      true,
		"/srv/app/package-lock.json": true,
		"/srv/app/yarn.lock":         true,
		// Java
		"/srv/app/pom.xml":          true,
		"/srv/app/build.gradle":     true,
		"/srv/app/build.gradle.kts": true,
		"/srv/app/gradle.lockfile":  true,
		// Not dep files
		"/srv/app/main.py":       false,
		"/srv/app/README.md":     false,
		"/srv/app/yarn.lock.bak": false,
	}
	for path, want := range cases {
		got := isDepsEcosystemFile(path)
		assert.Equal(t, want, got, "path=%s", path)
	}
}

// --- Python requirements.txt ---

const pyRequirementsTxt = `# App requirements
cryptography==41.0.7
pynacl>=1.5.0
bcrypt==4.0.1
pyjwt[crypto]==2.8.0
requests==2.31.0
flask==3.0.0
# Legacy — deprecated
pycrypto==2.6.1
`

func TestParsePythonRequirements(t *testing.T) {
	t.Parallel()
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	findings := m.parsePythonRequirements("/srv/app/requirements.txt", []byte(pyRequirementsTxt))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "cryptography")
	assert.Contains(t, joined, "pynacl")
	assert.Contains(t, joined, "bcrypt")
	assert.Contains(t, joined, "pyjwt")
	// Non-crypto deps must NOT produce findings.
	assert.NotContains(t, joined, "requests")
	assert.NotContains(t, joined, "flask")
	// Deprecated pycrypto should show up.
	assert.Contains(t, joined, "pycrypto")
}

// --- Python pyproject.toml ---

const pyProjectToml = `[project]
name = "myapp"
version = "1.0"
dependencies = [
    "cryptography>=41.0.0",
    "flask>=3.0.0",
    "pyjwt[crypto]>=2.0",
]

[tool.poetry.dependencies]
python = "^3.11"
cryptography = "^41.0"
bcrypt = "^4.0"
django = "^5.0"
`

func TestParsePyProjectToml(t *testing.T) {
	t.Parallel()
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	findings := m.parsePyProjectToml("/srv/app/pyproject.toml", []byte(pyProjectToml))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "cryptography")
	assert.Contains(t, joined, "bcrypt")
	assert.Contains(t, joined, "pyjwt")
}

// --- Node package.json ---

const nodePackageJSON = `{
  "name": "myapp",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "crypto-js": "^4.2.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "tweetnacl": "^1.0.3"
  },
  "devDependencies": {
    "mocha": "^10.2.0",
    "node-forge": "^1.3.1"
  }
}`

func TestParseNodePackageJSON(t *testing.T) {
	t.Parallel()
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	findings := m.parseNodePackageJSON("/srv/app/package.json", []byte(nodePackageJSON))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "crypto-js")
	assert.Contains(t, joined, "bcryptjs")
	assert.Contains(t, joined, "jsonwebtoken")
	assert.Contains(t, joined, "tweetnacl")
	assert.Contains(t, joined, "node-forge")
	// Non-crypto excluded.
	assert.NotContains(t, joined, "express")
	assert.NotContains(t, joined, "mocha")
}

// --- Java pom.xml ---

const javaPomXML = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.77</version>
    </dependency>
    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt-api</artifactId>
      <version>0.12.3</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <version>3.2.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.12.0</version>
    </dependency>
  </dependencies>
</project>`

func TestParseJavaPomXML(t *testing.T) {
	t.Parallel()
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	findings := m.parseJavaPomXML("/srv/app/pom.xml", []byte(javaPomXML))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "bouncycastle")
	assert.Contains(t, joined, "jsonwebtoken")
	assert.Contains(t, joined, "tink")
	// Non-crypto excluded.
	assert.NotContains(t, joined, "spring-boot")
}

// TestParseJavaPomXML_DependencyManagementStripped is the SF3
// regression test. Before the fix, a <dependencyManagement>
// block declaring a version constraint for BouncyCastle would
// produce a finding even when the project never actually
// referenced that artifact in its real <dependencies> list.
// The fix strips management blocks before the dependency
// regex runs.
func TestParseJavaPomXML_DependencyManagementStripped(t *testing.T) {
	t.Parallel()
	const pomWithDepMgmt = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.77</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
    </dependency>
  </dependencies>
</project>`
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	findings := m.parseJavaPomXML("/srv/app/pom.xml", []byte(pomWithDepMgmt))
	// No actual crypto dependency is declared — BouncyCastle is
	// only in dependencyManagement. Findings should be empty.
	for _, f := range findings {
		if f.CryptoAsset != nil {
			assert.NotContains(t, f.CryptoAsset.Algorithm, "bouncycastle",
				"dependencyManagement-only BouncyCastle leaked as a finding")
		}
	}
}

// --- Java build.gradle ---

const javaBuildGradle = `plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.77'
    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
}
`

func TestParseJavaBuildGradle(t *testing.T) {
	t.Parallel()
	m := NewDepsEcosystemsModule(&scannerconfig.Config{})
	findings := m.parseJavaBuildGradle("/srv/app/build.gradle", []byte(javaBuildGradle))
	require.NotEmpty(t, findings)

	algos := collectAlgorithms(findings)
	joined := strings.Join(algos, " ")
	assert.Contains(t, joined, "bouncycastle")
	assert.Contains(t, joined, "jsonwebtoken")
	// Non-crypto excluded.
	assert.NotContains(t, joined, "spring-boot")
	assert.NotContains(t, joined, "junit")
}

// --- End-to-end walk ---

func TestDepsEcosystemsModule_ScanWalk(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte(pyRequirementsTxt), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"), []byte(nodePackageJSON), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "pom.xml"), []byte(javaPomXML), 0o644))

	m := NewDepsEcosystemsModule(&scannerconfig.Config{MaxDepth: 5, MaxFileSize: 1024 * 1024})

	findings := make(chan *model.Finding, 100)
	done := make(chan struct{})
	var collected []*model.Finding
	go func() {
		for f := range findings {
			collected = append(collected, f)
		}
		close(done)
	}()

	err := m.Scan(context.Background(), model.ScanTarget{Type: model.TargetFilesystem, Value: tmp, Depth: 5}, findings)
	require.NoError(t, err)
	close(findings)
	<-done

	require.NotEmpty(t, collected)
	// Should cover all three ecosystems.
	ecosystems := make(map[string]bool)
	for _, f := range collected {
		assert.Equal(t, "deps_ecosystems", f.Module)
		if f.CryptoAsset != nil && f.CryptoAsset.Purpose != "" {
			for _, lang := range []string{"Python", "Node", "Java"} {
				if strings.Contains(f.CryptoAsset.Purpose, lang) {
					ecosystems[lang] = true
				}
			}
		}
	}
	assert.True(t, ecosystems["Python"], "Python ecosystem missing from findings")
	assert.True(t, ecosystems["Node"], "Node ecosystem missing from findings")
	assert.True(t, ecosystems["Java"], "Java ecosystem missing from findings")
}
