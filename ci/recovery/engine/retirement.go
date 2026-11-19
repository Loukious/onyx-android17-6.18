// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

const retiredSUSFSName = "susfs_guard_lkm"
const retiredSUSFSSHA256 = "737ea429fe37078682c2574a1e6a03b055269b459f8cc4a6a646415010a538e0"

type builtinSUSFS struct {
	Implementation  string `json:"implementation"`
	BuiltIn         bool   `json:"built_in"`
	SourceRevision  string `json:"source_revision"`
	SourceSHA256    string `json:"source_sha256"`
	Version         string `json:"version"`
	RuntimeVerified bool   `json:"runtime_verified"`
}

var revisionSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sourceSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var retiredSUSFSRelease = regexp.MustCompile(`^6\.18\.[0-9]+-android17-[0-9]+-[a-zA-Z0-9.-]+-onyx-balanced(?: |$)`)

func (p *kernelPackage) validateRetiredModules() error {
	if len(p.RetiredModules) == 0 {
		return nil
	}
	if p.SUSFS == nil || !p.SUSFS.BuiltIn || p.SUSFS.Implementation != "wildkernels-builtin" ||
		!revisionSHA.MatchString(p.SUSFS.SourceRevision) || !sourceSHA.MatchString(p.SUSFS.SourceSHA256) || p.SUSFS.Version != "v2.4.0" {
		return fmt.Errorf("module retirement requires verified built-in SUSFS provenance")
	}
	hashes, ok := p.RetiredModules[retiredSUSFSName]
	if len(p.RetiredModules) != 1 || !ok || len(hashes) != 1 || hashes[0] != retiredSUSFSSHA256 {
		return fmt.Errorf("module retirement policy differs from the reviewed SUSFS binary")
	}
	if _, exists := p.Modules[retiredSUSFSName]; exists || slices.Contains(p.Builtin, retiredSUSFSName) {
		return fmt.Errorf("retired SUSFS module cannot also be shipped or relabelled as builtin")
	}
	for name, module := range p.Modules {
		for _, dependency := range append(append(append([]string{}, module.Depends...), module.Pre...), module.Post...) {
			if dependency == retiredSUSFSName {
				return fmt.Errorf("module %s references retired SUSFS", name)
			}
		}
	}
	if p.Loading != nil {
		for _, group := range p.Loading.Groups {
			for _, file := range group.Modules {
				if normalizeModule(file) == retiredSUSFSName {
					return fmt.Errorf("module loading policy references retired SUSFS")
				}
			}
		}
	}
	return nil
}

func retiredSUSFSReferences(old moduleDirectory) error {
	for file, contents := range old.Config {
		for _, line := range strings.Split(string(contents), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			if file == "modules.dep" {
				owner, dependencies, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				for _, dependency := range strings.Fields(dependencies) {
					if normalizeModule(dependency) == retiredSUSFSName || normalizeModule(owner) == retiredSUSFSName {
						return fmt.Errorf("ordinary dependency table references retired SUSFS")
					}
				}
			} else if file == "modules.load" || strings.HasPrefix(file, "modules.load.") || file == "modules.alias" || file == "modules.softdep" {
				for _, field := range strings.Fields(line) {
					if normalizeModule(field) == retiredSUSFSName {
						return fmt.Errorf("%s references retired SUSFS", file)
					}
				}
			}
		}
	}
	return nil
}

func (p *kernelPackage) verifyRetiredModule(role string, old moduleDirectory, file string) (bool, error) {
	if _, allowed := p.RetiredModules[normalizeModule(file)]; !allowed {
		return false, nil
	}
	if role != "vendor_dlkm" || file != retiredSUSFSName+".ko" {
		return false, fmt.Errorf("reviewed SUSFS retirement is limited to vendor_dlkm")
	}
	if err := retiredSUSFSReferences(old); err != nil {
		return false, err
	}
	data, ok := old.Data[file]
	if !ok {
		path, exists := old.Sources[file]
		if !exists {
			return false, fmt.Errorf("retired module binary is missing")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return false, fmt.Errorf("unsupported retired module file")
		}
		data, err = os.ReadFile(path)
		if err != nil {
			return false, err
		}
	}
	if len(data) > 64<<20 {
		return false, fmt.Errorf("retired module is too large")
	}
	binary, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return false, fmt.Errorf("retired module is not ELF: %w", err)
	}
	defer binary.Close()
	if binary.Class != elf.ELFCLASS64 || binary.Data != elf.ELFDATA2LSB || binary.Machine != elf.EM_AARCH64 || binary.Type != elf.ET_REL {
		return false, fmt.Errorf("retired module is not an ARM64 kernel object")
	}
	section := binary.Section(".modinfo")
	if section == nil || section.Size > 1<<20 || section.Flags&elf.SHF_COMPRESSED != 0 {
		return false, fmt.Errorf("retired module has no supported modinfo")
	}
	metadata, err := section.Data()
	if err != nil {
		return false, err
	}
	fields := make(map[string]string)
	for _, record := range bytes.Split(metadata, []byte{0}) {
		key, value, ok := strings.Cut(string(record), "=")
		if !ok || (key != "name" && key != "vermagic" && key != "depends") {
			continue
		}
		if _, duplicate := fields[key]; duplicate {
			return false, fmt.Errorf("duplicate retired module identity field")
		}
		fields[key] = value
	}
	if fields["name"] != retiredSUSFSName || !retiredSUSFSRelease.MatchString(fields["vermagic"]) || fields["depends"] != "" {
		return false, fmt.Errorf("retired module identity, 6.18 vermagic or dependency list differs")
	}
	sum := sha256.Sum256(data)
	if !slices.Contains(p.RetiredModules[retiredSUSFSName], hex.EncodeToString(sum[:])) {
		return false, fmt.Errorf("retired SUSFS binary hash is not reviewed")
	}
	fmt.Printf("%s: retiring verified SUSFS LKM replaced by the built-in implementation\n", role)
	return true, nil
}
