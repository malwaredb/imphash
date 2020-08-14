package imphash

import (
	"bytes"
	"crypto/md5"
	"debug/elf"
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
	for _, dllName := range libNames {
		sort.Strings(libFunc[dllName])
		for idx, funcName := range libFunc[dllName] {
			if idx > 0 {
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