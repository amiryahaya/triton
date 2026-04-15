package cli

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// fixtureAssembly is the in-memory shape of a synthetic assembly built for tests.
type fixtureAssembly struct {
	TypeRefs    []TypeRef
	UserStrings []string
}

// FixtureAssembly is exported so cross-package integration tests can build
// fixtures without the .NET SDK.
type FixtureAssembly = fixtureAssembly

// BuildAssembly is the exported wrapper around buildAssembly. Used by the
// dotnet_il integration test so it doesn't have to vendor the PE+CLI builder.
func BuildAssembly(t *testing.T, fa FixtureAssembly) []byte {
	return buildAssembly(t, fa)
}

// buildAssembly returns bytes that satisfy LocateCLIMetadata + parseTablesStream + parseUSHeap.
// The PE wrapper is the minimum: MZ stub, PE sig, file header, optional header (PE32),
// one .text section containing CLI header + metadata blob.
func buildAssembly(t *testing.T, fa fixtureAssembly) []byte {
	t.Helper()

	// --- 1. Build #Strings heap and record offsets ---
	stringsHeap := []byte{0x00} // index 0 reserved
	type nsName struct{ ns, name uint16 }
	rows := make([]nsName, len(fa.TypeRefs))
	addStr := func(s string) uint16 {
		off := uint16(len(stringsHeap))
		stringsHeap = append(stringsHeap, []byte(s)...)
		stringsHeap = append(stringsHeap, 0)
		return off
	}
	for i, r := range fa.TypeRefs {
		rows[i].ns = addStr(r.Namespace)
		rows[i].name = addStr(r.Name)
	}
	for len(stringsHeap)%4 != 0 {
		stringsHeap = append(stringsHeap, 0)
	}

	// --- 2. Build #US heap ---
	usHeap := []byte{0x00}
	for _, s := range fa.UserStrings {
		var u []byte
		for _, r := range s {
			u = append(u, byte(r), byte(r>>8))
		}
		u = append(u, 0)                      // terminal
		usHeap = append(usHeap, byte(len(u))) // 1-byte compressed length
		usHeap = append(usHeap, u...)
	}
	for len(usHeap)%4 != 0 {
		usHeap = append(usHeap, 0)
	}

	// --- 3. Build #~ tables stream (TypeRef table only) ---
	var tablesBuf bytes.Buffer
	binary.Write(&tablesBuf, binary.LittleEndian, uint32(0))
	tablesBuf.WriteByte(2)
	tablesBuf.WriteByte(0)
	tablesBuf.WriteByte(0)
	tablesBuf.WriteByte(1)
	binary.Write(&tablesBuf, binary.LittleEndian, uint64(1<<tableTypeRef))
	binary.Write(&tablesBuf, binary.LittleEndian, uint64(0))
	binary.Write(&tablesBuf, binary.LittleEndian, uint32(len(rows)))
	for _, r := range rows {
		binary.Write(&tablesBuf, binary.LittleEndian, uint16(0))
		binary.Write(&tablesBuf, binary.LittleEndian, r.name)
		binary.Write(&tablesBuf, binary.LittleEndian, r.ns)
	}
	for tablesBuf.Len()%4 != 0 {
		tablesBuf.WriteByte(0)
	}

	// --- 4. Build metadata root + stream headers ---
	type streamSpec struct {
		name string
		data []byte
	}
	streams := []streamSpec{
		{"#~", tablesBuf.Bytes()},
		{"#Strings", stringsHeap},
		{"#US", usHeap},
	}
	var streamData bytes.Buffer
	type streamHeader struct {
		offset uint32
		size   uint32
		name   string
	}
	headers := make([]streamHeader, len(streams))
	for i, s := range streams {
		headers[i] = streamHeader{
			offset: uint32(streamData.Len()),
			size:   uint32(len(s.data)),
			name:   s.name,
		}
		streamData.Write(s.data)
	}

	var rootBuf bytes.Buffer
	binary.Write(&rootBuf, binary.LittleEndian, uint32(0x424A5342)) // 'BSJB'
	binary.Write(&rootBuf, binary.LittleEndian, uint16(1))
	binary.Write(&rootBuf, binary.LittleEndian, uint16(1))
	binary.Write(&rootBuf, binary.LittleEndian, uint32(0))
	versionStr := "v4.0.30319"
	versionPadded := make([]byte, ((len(versionStr)+1+3)/4)*4)
	copy(versionPadded, versionStr)
	binary.Write(&rootBuf, binary.LittleEndian, uint32(len(versionPadded)))
	rootBuf.Write(versionPadded)
	binary.Write(&rootBuf, binary.LittleEndian, uint16(0))
	binary.Write(&rootBuf, binary.LittleEndian, uint16(len(streams)))

	headersSize := 0
	for _, h := range headers {
		nameBuf := make([]byte, ((len(h.name)+1+3)/4)*4)
		copy(nameBuf, h.name)
		headersSize += 8 + len(nameBuf)
	}
	dataStart := uint32(rootBuf.Len() + headersSize)

	for _, h := range headers {
		nameBuf := make([]byte, ((len(h.name)+1+3)/4)*4)
		copy(nameBuf, h.name)
		binary.Write(&rootBuf, binary.LittleEndian, dataStart+h.offset)
		binary.Write(&rootBuf, binary.LittleEndian, h.size)
		rootBuf.Write(nameBuf)
	}
	rootBuf.Write(streamData.Bytes())
	metadata := rootBuf.Bytes()

	// --- 5. Build CLI header (72 bytes per ECMA-335 §II.25.3.3) ---
	cliHeader := make([]byte, 72)
	binary.LittleEndian.PutUint32(cliHeader[0:], 72)
	binary.LittleEndian.PutUint16(cliHeader[4:], 2)
	binary.LittleEndian.PutUint16(cliHeader[6:], 5)
	binary.LittleEndian.PutUint32(cliHeader[16:], 1) // Flags = IL only

	// --- 6. Build minimal PE wrapper ---
	const (
		dosStubSize     = 64
		peSigSize       = 4
		coffHeaderSize  = 20
		optionalHdrSize = 224
		sectionHdrSize  = 40
	)
	textSectionRVA := uint32(0x2000)
	fileAlignment := uint32(0x200)
	sectionAlignment := uint32(0x1000)
	textRawOff := uint32(dosStubSize + peSigSize + coffHeaderSize + optionalHdrSize + sectionHdrSize)
	if textRawOff%fileAlignment != 0 {
		textRawOff = ((textRawOff / fileAlignment) + 1) * fileAlignment
	}

	cliHeaderRVA := textSectionRVA
	metadataRVA := cliHeaderRVA + uint32(len(cliHeader))
	binary.LittleEndian.PutUint32(cliHeader[8:], metadataRVA)
	binary.LittleEndian.PutUint32(cliHeader[12:], uint32(len(metadata)))

	textData := append(append([]byte{}, cliHeader...), metadata...)
	textRawSize := uint32(((len(textData) + int(fileAlignment) - 1) / int(fileAlignment)) * int(fileAlignment))
	textPadded := make([]byte, textRawSize)
	copy(textPadded, textData)

	textVirtSize := uint32(len(textData))
	sizeOfImage := textSectionRVA + textVirtSize
	if sizeOfImage%sectionAlignment != 0 {
		sizeOfImage = ((sizeOfImage / sectionAlignment) + 1) * sectionAlignment
	}
	sizeOfHeaders := textRawOff

	out := make([]byte, int(textRawOff)+int(textRawSize))
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[60:], dosStubSize)

	off := dosStubSize
	copy(out[off:], []byte("PE\x00\x00"))
	off += peSigSize

	// COFF file header
	binary.LittleEndian.PutUint16(out[off:], 0x14C) // Machine = i386
	binary.LittleEndian.PutUint16(out[off+2:], 1)   // NumberOfSections
	binary.LittleEndian.PutUint16(out[off+16:], optionalHdrSize)
	binary.LittleEndian.PutUint16(out[off+18:], 0x2102) // Characteristics
	off += coffHeaderSize

	// Optional header (PE32)
	binary.LittleEndian.PutUint16(out[off:], 0x10B)             // Magic PE32
	binary.LittleEndian.PutUint32(out[off+16:], textSectionRVA) // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(out[off+20:], textSectionRVA) // BaseOfCode
	binary.LittleEndian.PutUint32(out[off+28:], 0x400000)       // ImageBase
	binary.LittleEndian.PutUint32(out[off+32:], sectionAlignment)
	binary.LittleEndian.PutUint32(out[off+36:], fileAlignment)
	binary.LittleEndian.PutUint32(out[off+56:], sizeOfImage)
	binary.LittleEndian.PutUint32(out[off+60:], sizeOfHeaders)
	binary.LittleEndian.PutUint16(out[off+68:], 3)  // Subsystem = console
	binary.LittleEndian.PutUint32(out[off+92:], 16) // NumberOfRvaAndSizes
	dataDirOff := off + 96 + 14*8
	binary.LittleEndian.PutUint32(out[dataDirOff:], cliHeaderRVA)
	binary.LittleEndian.PutUint32(out[dataDirOff+4:], uint32(len(cliHeader)))
	off += optionalHdrSize

	// Section header
	copy(out[off:off+8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(out[off+8:], textVirtSize)    // VirtualSize
	binary.LittleEndian.PutUint32(out[off+12:], textSectionRVA) // VirtualAddress
	binary.LittleEndian.PutUint32(out[off+16:], textRawSize)    // SizeOfRawData
	binary.LittleEndian.PutUint32(out[off+20:], textRawOff)     // PointerToRawData
	binary.LittleEndian.PutUint32(out[off+36:], 0x60000020)     // Characteristics
	off += sectionHdrSize

	copy(out[textRawOff:], textPadded)
	return out
}
