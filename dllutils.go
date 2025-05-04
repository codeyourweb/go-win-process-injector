package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

func findSymbolRVA(PEpath string, symbolName string) (uint32, error) {
	f, err := os.Open(PEpath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		return 0, err
	}
	defer peFile.Close()

	exportDir := peFile.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		exportDir = peFile.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		if exportDir.VirtualAddress == 0 {
			return 0, fmt.Errorf("no export directory found")
		}
	}

	var exportTable *pe.Section
	for _, section := range peFile.Sections {
		if uint32(exportDir.VirtualAddress) >= section.VirtualAddress &&
			uint32(exportDir.VirtualAddress) < section.VirtualAddress+section.Size {
			exportTable = section
			break
		}
	}
	if exportTable == nil {
		return 0, fmt.Errorf("could not find export section")
	}

	exportData, err := exportTable.Data()
	if err != nil {
		return 0, fmt.Errorf("could not read export data: %w", err)
	}

	exportDirRVA := uint32(exportDir.VirtualAddress)
	exportDirOffset := exportDirRVA - exportTable.VirtualAddress

	exportDirectory := struct {
		Characteristics       uint32
		TimeDateStamp         uint32
		MajorVersion          uint16
		MinorVersion          uint16
		Name                  uint32
		Base                  uint32
		NumberOfFunctions     uint32
		NumberOfNames         uint32
		AddressOfFunctions    uint32
		AddressOfNames        uint32
		AddressOfNameOrdinals uint32
	}{}

	err = binary.Read(bytes.NewReader(exportData[exportDirOffset:]), binary.LittleEndian, &exportDirectory)
	if err != nil {
		return 0, fmt.Errorf("could not read export directory: %w", err)
	}

	namesOffset := exportDirectory.AddressOfNames - exportTable.VirtualAddress
	ordinalsOffset := exportDirectory.AddressOfNameOrdinals - exportTable.VirtualAddress

	for i := 0; i < int(exportDirectory.NumberOfNames); i++ {
		var nameRVA uint32
		err = binary.Read(bytes.NewReader(exportData[namesOffset+uint32(i)*4:]), binary.LittleEndian, &nameRVA)
		if err != nil {
			return 0, fmt.Errorf("could not read name RVA: %w", err)
		}

		nameOffset := nameRVA - exportTable.VirtualAddress
		name := ""
		for j := nameOffset; j < uint32(len(exportData)); j++ {
			if exportData[j] == 0 {
				break
			}
			name += string(exportData[j])
		}

		if name == symbolName {
			var ordinal uint16
			err = binary.Read(bytes.NewReader(exportData[ordinalsOffset+uint32(i)*2:]), binary.LittleEndian, &ordinal)
			if err != nil {
				return 0, fmt.Errorf("could not read ordinal: %w", err)
			}

			functionsTableOffsetInData := (exportDirectory.AddressOfFunctions) - (exportTable.VirtualAddress)
			functionAddressOffset := functionsTableOffsetInData + uint32(ordinal)*4

			if int(functionAddressOffset)+4 > len(exportData) {
				return 0, fmt.Errorf("reading outside limit of exportedData")
			}

			var rawFunctionAddress uint32
			err = binary.Read(bytes.NewReader(exportData[functionAddressOffset:]), binary.LittleEndian, &rawFunctionAddress)
			if err != nil {
				return 0, fmt.Errorf("could not read raw function address: %w", err)
			}

			return rawFunctionAddress, nil
		}
	}

	return 0, fmt.Errorf("symbol %s not found in export table", symbolName)
}
