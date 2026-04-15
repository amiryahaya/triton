// Package cli parses .NET CLI (Common Language Infrastructure) metadata
// from PE assemblies per ECMA-335. Used by the dotnet_il scanner to extract
// crypto type references and string literals embedded in compiled assemblies,
// where source scanners can't reach.
//
// Scope: metadata streams only (#~, #Strings, #US). No IL bytecode walking.
// Endianness: all CLI metadata is little-endian.
package cli

// Assembly is the result of parsing a .NET PE assembly's metadata.
type Assembly struct {
	// TypeRefs are fully-qualified type names referenced by the assembly,
	// e.g. "System.Security.Cryptography.RSACryptoServiceProvider".
	TypeRefs []string
	// UserStrings are string literals from the #US heap, e.g. algorithm
	// identifier strings passed to factories.
	UserStrings []string
}

// TypeRef is a single TypeRef table row resolved against the strings + assembly-ref heaps.
type TypeRef struct {
	Namespace string
	Name      string
}

// FullName returns "Namespace.Name" or just "Name" when namespace is empty.
func (t TypeRef) FullName() string {
	if t.Namespace == "" {
		return t.Name
	}
	return t.Namespace + "." + t.Name
}
