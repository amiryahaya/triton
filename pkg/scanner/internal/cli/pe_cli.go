package cli

import (
	"debug/pe"
	"errors"
	"fmt"
	"io"
)

// metadataSignature is the 4-byte little-endian signature 'BSJB' at the
// start of every .NET metadata root (ECMA-335 §II.24.2.1).
const metadataSignature = uint32(0x424A5342)

// LocateCLIMetadata opens the PE at r, follows the CLR Runtime Header data
// directory (#14) to the CLI header, then returns the file offset + size of
// the metadata root.
func LocateCLIMetadata(r io.ReaderAt) (offset, size uint32, err error) {
	pf, err := pe.NewFile(readerAtAdapter{r})
	if err != nil {
		return 0, 0, fmt.Errorf("cli: pe.NewFile: %w", err)
	}
	defer func() { _ = pf.Close() }()

	var clrRVA, clrSize uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) <= 14 {
			return 0, 0, errors.New("cli: PE has no CLR data directory")
		}
		clrRVA = oh.DataDirectory[14].VirtualAddress
		clrSize = oh.DataDirectory[14].Size
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) <= 14 {
			return 0, 0, errors.New("cli: PE has no CLR data directory")
		}
		clrRVA = oh.DataDirectory[14].VirtualAddress
		clrSize = oh.DataDirectory[14].Size
	default:
		return 0, 0, errors.New("cli: unknown PE optional header")
	}
	if clrRVA == 0 || clrSize == 0 {
		return 0, 0, errors.New("cli: PE is not a .NET assembly (no CLR header)")
	}

	cliHeader, err := readRVA(pf, clrRVA, 72)
	if err != nil {
		return 0, 0, fmt.Errorf("cli: read CLI header: %w", err)
	}
	metadataRVA := uint32(cliHeader[8]) | uint32(cliHeader[9])<<8 | uint32(cliHeader[10])<<16 | uint32(cliHeader[11])<<24
	metadataSize := uint32(cliHeader[12]) | uint32(cliHeader[13])<<8 | uint32(cliHeader[14])<<16 | uint32(cliHeader[15])<<24

	fileOff, err := rvaToFileOffset(pf, metadataRVA)
	if err != nil {
		return 0, 0, fmt.Errorf("cli: metadata RVA: %w", err)
	}
	sigBuf := make([]byte, 4)
	if _, err := r.ReadAt(sigBuf, int64(fileOff)); err != nil {
		return 0, 0, fmt.Errorf("cli: read metadata sig: %w", err)
	}
	sig := uint32(sigBuf[0]) | uint32(sigBuf[1])<<8 | uint32(sigBuf[2])<<16 | uint32(sigBuf[3])<<24
	if sig != metadataSignature {
		return 0, 0, fmt.Errorf("cli: bad metadata signature 0x%08x", sig)
	}
	return fileOff, metadataSize, nil
}

func readRVA(pf *pe.File, rva, size uint32) ([]byte, error) {
	for _, s := range pf.Sections {
		end := uint64(rva) + uint64(size)
		sectionEnd := uint64(s.VirtualAddress) + uint64(s.VirtualSize)
		if uint64(rva) < uint64(s.VirtualAddress) || end > sectionEnd {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil, err
		}
		start := rva - s.VirtualAddress
		if int(start)+int(size) > len(data) {
			return nil, errors.New("cli: RVA past end of section data")
		}
		return data[start : start+size], nil
	}
	return nil, fmt.Errorf("cli: RVA 0x%x not in any section", rva)
}

func rvaToFileOffset(pf *pe.File, rva uint32) (uint32, error) {
	for _, s := range pf.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s.Offset + (rva - s.VirtualAddress), nil
		}
	}
	return 0, fmt.Errorf("cli: RVA 0x%x not in any section", rva)
}

type readerAtAdapter struct{ io.ReaderAt }
