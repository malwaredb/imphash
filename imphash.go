package imphash

import (
	"bytes"
	"crypto/md5"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"sort"
	"strings"
	"github.com/glaslos/ssdeep"
)

type ImpHashResult struct {
	ImpHash string
	ImpFuzzy string
	ImpString string
}

func ImpHashFromBytes(fileContents []byte) (*ImpHashResult, error) {
	if bytes.HasPrefix(fileContents, []byte{0x4d, 0x5a}) {
		return impHashFromPEBytes(fileContents)
	}
	if bytes.HasPrefix(fileContents, []byte{0x7f, 0x45, 0x4c, 0x46}) {
		return impHashFromELFBytes(fileContents)
	}
	if bytes.HasPrefix(fileContents, []byte{0xfe, 0xed, 0xfa, 0xce}) {
		return impHashFromMachO(fileContents)
	}
	if bytes.HasPrefix(fileContents, []byte{0xca, 0xfe, 0xba, 0xbe}) {
		return impHashFromFatMachO(fileContents)
	}
	return nil, errors.New("File type not supported")
}

func impHashFromPEBytes(fileContents []byte) (*ImpHashResult, error) {
	fileReader := bytes.NewReader(fileContents)
	pefile, err := pe.NewFile(fileReader)
	if err != nil {
		return nil, err
	}

	defer pefile.Close()
	libs, err := pefile.ImportedSymbols()
	if err != nil {
		return nil, err
	}

	impHashes := &ImpHashResult{}

	dllNames := make([]string, 0)
	dllFunc := make(map[string][]string, 0)
	for _, lib := range libs {
		//fmt.Println(lib)
		if !strings.Contains(lib, ":") {
			continue
		}
		parts := strings.Split(lib, ":")
		dllName := strings.ToLower(parts[1])
		if strings.HasSuffix(dllName, ".dll") {
			dllName = strings.Replace(dllName, ".dll", "", 1)
		} else {
			if strings.HasSuffix(dllName, ".sys") {
				dllName = strings.Replace(dllName, ".sys", "", 1)
			}
		}
		funcName := strings.ToLower(parts[0])
		dllFunc[dllName] = append(dllFunc[dllName], funcName)
	}


	for dllName := range dllFunc {
		dllNames = append(dllNames, dllName)
	}

	sort.Strings(dllNames) // Gives a new ImpHash than Python's pefile, but now we don't care about reordering to evade ImpHash
	impString := ""
	for idx1, dllName := range dllNames {
		sort.Strings(dllFunc[dllName])
		for idx2, funcName := range dllFunc[dllName] {
			if idx1+idx2 > 0 {
				impString += ","
			}
			impString += dllName + "." + funcName
		}
	}

	impHashes.ImpHash = fmt.Sprintf("%x", md5.Sum([]byte(impString)))
	impHashes.ImpFuzzy, _ = ssdeep.FuzzyBytes([]byte(impString))
	impHashes.ImpString = impString
	return impHashes, nil
}

func impHashFromELFBytes(fileContents []byte) (*ImpHashResult, error) {
	fileReader := bytes.NewReader(fileContents)
	e, err := elf.NewFile(fileReader)
	if err != nil {
		return nil, err
	}

	defer e.Close()

	libs, err := e.ImportedSymbols()
	if err != nil {
		return nil, err
	}

	libFunc := make(map[string][]string, 0)
	for _, lib := range libs {
		libname := lib.Library
		soIdx := strings.Index(libname, ".so")
		if soIdx > 0 {
			libname = libname[:soIdx]
		}
		libFunc[libname] = append(libFunc[libname], lib.Name)
	}

	libNames := make([]string, 0)
	for lib := range libFunc {
		libNames = append(libNames, lib)
	}
	sort.Strings(libNames)

	impString := ""
	for idx1, dllName := range libNames {
		sort.Strings(libFunc[dllName])
		for idx2, funcName := range libFunc[dllName] {
			if idx1+idx2 > 0 {
				impString += ","
			}
			impString += dllName + "." + funcName
		}
	}

	impHashes := &ImpHashResult{}
	impHashes.ImpHash = fmt.Sprintf("%x", md5.Sum([]byte(impString)))
	impHashes.ImpFuzzy, _ = ssdeep.FuzzyBytes([]byte(impString))
	impHashes.ImpString = impString
	return impHashes, nil
}

func impHashFromMachO(fileContents []byte) (*ImpHashResult, error) {
	fileReader := bytes.NewReader(fileContents)
	m, err := macho.NewFile(fileReader)
	if err != nil {
		return nil, err
	}

	libs, err := m.ImportedLibraries()
	if err != nil {
		return nil, err
	}

	libFunc := make(map[string]int, 0)
	for _, lib := range libs {
		libname := lib
		soIdx := strings.Index(libname, ".dylib")
		if soIdx > 0 {
			libname = libname[:soIdx]
		}
		libFunc[libname] = 1
	}

	symbols, err := m.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	for _, symb := range symbols {
		libFunc[symb] = 1
	}

	libNames := make([]string, 0)
	for lib := range libFunc {
		libNames = append(libNames, lib)
	}
	sort.Strings(libNames)

	impString := ""
	for idx, dllName := range libNames {
		if idx > 0 {
			impString += ","
		}
		impString += dllName
	}

	impHashes := &ImpHashResult{}
	impHashes.ImpHash = fmt.Sprintf("%x", md5.Sum([]byte(impString)))
	impHashes.ImpFuzzy, _ = ssdeep.FuzzyBytes([]byte(impString))
	impHashes.ImpString = impString
	return impHashes, nil
}

func impHashFromFatMachO(fileContents []byte) (*ImpHashResult, error) {
	fileReader := bytes.NewReader(fileContents)
	m, err := macho.NewFatFile(fileReader)
	if err != nil {
		return nil, err
	}

	libFunc := make(map[string]int, 0) // Using it as a set
	for _, arch := range m.Arches {
		libs, err := arch.ImportedLibraries()
		if err != nil {
			return nil, err
		}

		for _, lib := range libs {
			libname := lib
			soIdx := strings.Index(libname, ".dylib")
			if soIdx > 0 {
				libname = libname[:soIdx]
			}
			libFunc[libname] = 1
		}

		symbols, err := arch.ImportedSymbols()
		if err != nil {
			return nil, err
		}
		for _, symb := range symbols {
			libFunc[symb] = 1
		}
	}

	libNames := make([]string, 0)
	for lib := range libFunc {
		libNames = append(libNames, lib)
	}

	sort.Strings(libNames)
	impString := ""
	for idx, dllName := range libNames {
		if idx > 0 {
			impString += ","
		}
		impString += dllName
	}

	impHashes := &ImpHashResult{}
	impHashes.ImpHash = fmt.Sprintf("%x", md5.Sum([]byte(impString)))
	impHashes.ImpFuzzy, _ = ssdeep.FuzzyBytes([]byte(impString))
	impHashes.ImpString = impString
	return impHashes, nil
}