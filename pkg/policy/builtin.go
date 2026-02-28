package policy

import (
	"embed"
	"sort"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// BuiltinPolicies maps policy names to their embedded YAML content.
var builtinPolicies = map[string]string{
	"nacsa-2030": "builtin/nacsa-2030.yaml",
	"cnsa-2.0":   "builtin/cnsa-2.0.yaml",
}

// LoadBuiltin loads a named builtin policy.
func LoadBuiltin(name string) (*Policy, error) {
	path, ok := builtinPolicies[name]
	if !ok {
		return nil, &ErrUnknownPolicy{Name: name}
	}
	data, err := builtinFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// ListBuiltin returns the names of all builtin policies.
func ListBuiltin() []string {
	names := make([]string, 0, len(builtinPolicies))
	for name := range builtinPolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ErrUnknownPolicy is returned when a builtin policy name is not recognized.
type ErrUnknownPolicy struct {
	Name string
}

func (e *ErrUnknownPolicy) Error() string {
	return "unknown builtin policy: " + e.Name
}
