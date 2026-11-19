// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func retirementFixture(t *testing.T) (*kernelPackage, moduleDirectory) {
	t.Helper()
	p := fixturePackage(t)
	p.SUSFS = &builtinSUSFS{Implementation: "wildkernels-builtin", BuiltIn: true,
		SourceRevision: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("b", 64), Version: "v2.4.0"}
	p.RetiredModules = map[string][]string{retiredSUSFSName: {retiredSUSFSSHA256}}
	old := moduleDirectory{Names: []string{"driver.ko", retiredSUSFSName + ".ko"},
		Data: map[string][]byte{retiredSUSFSName + ".ko": golden(t, "susfs-lkm-6.18.63")},
		Config: map[string][]byte{"modules.load": []byte("driver.ko\n"),
			"modules.dep":     []byte("driver.ko: dependency.ko\nsusfs_guard_lkm.ko:\n"),
			"modules.options": []byte("options driver firmware=test\n")}}
	return p, old
}

func TestBuiltinSUSFSRetiresOnlyTheReviewedUnloadedVendorAddon(t *testing.T) {
	for _, sourceFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "ramdisk-bytes", true: "erofs-file"}[sourceFile], func(t *testing.T) {
			p, old := retirementFixture(t)
			if sourceFile {
				path := filepath.Join(t.TempDir(), "susfs_guard_lkm.ko")
				if err := os.WriteFile(path, old.Data[retiredSUSFSName+".ko"], 0600); err != nil {
					t.Fatal(err)
				}
				old.Data = nil
				old.Sources = map[string]string{retiredSUSFSName + ".ko": path}
			}
			files, err := p.moduleFiles("vendor_dlkm", old, filepath.Join(t.TempDir(), "generated"))
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := files[retiredSUSFSName+".ko"]; exists {
				t.Fatal("retired addon is still shipped")
			}
			for _, module := range p.Modules {
				if files[module.File] == "" {
					t.Fatalf("ordinary driver was omitted: %s", module.File)
				}
			}
			load, _ := os.ReadFile(files["modules.load"])
			if string(load) != "driver.ko\nfeature.ko\n" {
				t.Fatalf("ordinary load order changed: %q", load)
			}
			options, _ := os.ReadFile(files["modules.options"])
			if !bytes.Equal(options, old.Config["modules.options"]) || len(p.Retired) != 0 {
				t.Fatal("feature retirement altered unrelated configuration or activated 6.6 migration")
			}
			if len(p.RetiredFeatures["vendor_dlkm"]) != 1 || p.RetiredFeatures["vendor_dlkm"][0] != retiredSUSFSName {
				t.Fatal("verified retirement was not recorded")
			}
		})
	}
}

func TestBuiltinSUSFSRetirementRejectsUnknownFilesAndUnsafeReferences(t *testing.T) {
	cases := map[string]func(*kernelPackage, *moduleDirectory){
		"missing_policy": func(p *kernelPackage, old *moduleDirectory) { p.RetiredModules = nil },
		"missing_binary": func(p *kernelPackage, old *moduleDirectory) { old.Data = nil },
		"symlink_binary": func(p *kernelPackage, old *moduleDirectory) {
			path := filepath.Join(t.TempDir(), "module.ko")
			if err := os.Symlink("missing-target", path); err != nil {
				t.Fatal(err)
			}
			old.Data = nil
			old.Sources = map[string]string{retiredSUSFSName + ".ko": path}
		},
		"new_loading_group": func(p *kernelPackage, old *moduleDirectory) {
			p.Loading = &moduleLoadingPolicy{SchemaVersion: 1, Default: "manual",
				Groups: []moduleLoadingGroup{{Modules: []string{retiredSUSFSName + ".ko"}}}}
		},
		"missing_provenance":   func(p *kernelPackage, old *moduleDirectory) { p.SUSFS = nil },
		"not_builtin":          func(p *kernelPackage, old *moduleDirectory) { p.SUSFS.BuiltIn = false },
		"other_implementation": func(p *kernelPackage, old *moduleDirectory) { p.SUSFS.Implementation = "lkm" },
		"missing_source":       func(p *kernelPackage, old *moduleDirectory) { p.SUSFS.SourceSHA256 = "" },
		"unknown_policy": func(p *kernelPackage, old *moduleDirectory) {
			p.RetiredModules["ordinary_driver"] = []string{retiredSUSFSSHA256}
		},
		"unreviewed_hash": func(p *kernelPackage, old *moduleDirectory) {
			p.RetiredModules[retiredSUSFSName] = []string{strings.Repeat("c", 64)}
		},
		"unknown_ordinary_module": func(p *kernelPackage, old *moduleDirectory) { old.Names = append(old.Names, "ordinary_driver.ko") },
		"non_elf": func(p *kernelPackage, old *moduleDirectory) {
			old.Data[retiredSUSFSName+".ko"] = []byte("not a module")
		},
		"wrong_arch": func(p *kernelPackage, old *moduleDirectory) { old.Data[retiredSUSFSName+".ko"][18] = 62 },
		"wrong_name": func(p *kernelPackage, old *moduleDirectory) {
			old.Data[retiredSUSFSName+".ko"] = bytes.ReplaceAll(old.Data[retiredSUSFSName+".ko"], []byte("name=susfs_guard_lkm"), []byte("name=other_guard_lkm"))
		},
		"wrong_vermagic": func(p *kernelPackage, old *moduleDirectory) {
			old.Data[retiredSUSFSName+".ko"] = bytes.ReplaceAll(old.Data[retiredSUSFSName+".ko"], []byte("vermagic=6.18."), []byte("vermagic=6.19."))
		},
		"tampered_binary": func(p *kernelPackage, old *moduleDirectory) {
			old.Data[retiredSUSFSName+".ko"] = append(old.Data[retiredSUSFSName+".ko"], 1)
		},
		"autoload": func(p *kernelPackage, old *moduleDirectory) {
			old.Config["modules.load"] = []byte("driver.ko\nsusfs_guard_lkm.ko\n")
		},
		"recovery_autoload": func(p *kernelPackage, old *moduleDirectory) {
			old.Config["modules.load.recovery"] = []byte("susfs_guard_lkm.ko\n")
		},
		"hard_dependency": func(p *kernelPackage, old *moduleDirectory) {
			old.Config["modules.dep"] = []byte("driver.ko: susfs_guard_lkm.ko\n")
		},
		"soft_dependency": func(p *kernelPackage, old *moduleDirectory) {
			old.Config["modules.softdep"] = []byte("softdep driver pre: susfs_guard_lkm\n")
		},
		"autoload_alias": func(p *kernelPackage, old *moduleDirectory) {
			old.Config["modules.alias"] = []byte("alias fixture susfs_guard_lkm\n")
		},
		"new_dependency": func(p *kernelPackage, old *moduleDirectory) {
			m := p.Modules["driver"]
			m.Depends = append(m.Depends, retiredSUSFSName)
			p.Modules["driver"] = m
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p, old := retirementFixture(t)
			change(p, &old)
			if _, err := p.moduleFiles("vendor_dlkm", old, filepath.Join(t.TempDir(), "rejected")); err == nil {
				t.Fatal("unsafe retirement was accepted")
			}
		})
	}
	for _, role := range []string{"system_dlkm", "recovery", "vendor_ramdisk"} {
		t.Run("wrong_partition_"+role, func(t *testing.T) {
			p, old := retirementFixture(t)
			if _, err := p.moduleFiles(role, old, filepath.Join(t.TempDir(), "rejected")); err == nil {
				t.Fatal("retirement from an unreviewed partition was accepted")
			}
		})
	}
}

func TestBuiltinSUSFSRetirementPolicySurvivesPackageDecoding(t *testing.T) {
	p, _ := retirementFixture(t)
	p.Format, p.Device, p.Compression = 1, "onyx", "lz4hc,level=12"
	for i := 0; len(p.Modules) < 300; i++ {
		name := fmt.Sprintf("catalog_fixture_%d", i)
		p.Modules[name] = kernelModule{File: name + ".ko", Kind: "gki"}
		if err := os.WriteFile(filepath.Join(p.Root, "payload/modules", name+".ko"), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"Image", "dtb.img", "dtbo.img"} {
		if err := os.WriteFile(filepath.Join(p.Root, "payload", name), []byte("fixture payload"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p.Hashes = make(map[string]string)
	for _, name := range []string{"Image", "dtb.img", "dtbo.img", "modules.builtin", "modules.builtin.modinfo"} {
		digest, err := fileSHA(filepath.Join(p.Root, "payload", name))
		if err != nil {
			t.Fatal(err)
		}
		p.Hashes["payload/"+name] = digest
	}
	for _, module := range p.Modules {
		digest, err := fileSHA(filepath.Join(p.Root, "payload/modules", module.File))
		if err != nil {
			t.Fatal(err)
		}
		p.Hashes["payload/modules/"+module.File] = digest
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Root, "kernel.json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	decoded, err := loadPackage(p.Root)
	if err != nil || !reflect.DeepEqual(decoded.RetiredModules, p.RetiredModules) || !reflect.DeepEqual(decoded.SUSFS, p.SUSFS) {
		t.Fatalf("verified policy did not survive package decoding: %v", err)
	}
}

func TestExistingLKMRecipeStillShipsItsAddon(t *testing.T) {
	p := fixturePackage(t)
	p.Modules[retiredSUSFSName] = kernelModule{File: retiredSUSFSName + ".ko", Kind: "platform"}
	if err := os.WriteFile(filepath.Join(p.Root, "payload/modules", retiredSUSFSName+".ko"), golden(t, "susfs-lkm-6.18.63"), 0600); err != nil {
		t.Fatal(err)
	}
	old := moduleDirectory{Names: []string{"driver.ko", retiredSUSFSName + ".ko"}, Config: map[string][]byte{"modules.load": []byte("driver.ko\n")}}
	files, err := p.moduleFiles("vendor_dlkm", old, filepath.Join(t.TempDir(), "generated"))
	if err != nil || files[retiredSUSFSName+".ko"] == "" || len(p.RetiredFeatures) != 0 {
		t.Fatalf("existing LKM recipe changed: %v", err)
	}
}

func TestBuiltinSUSFSRetirementRebuildsAnEROFSVendorImage(t *testing.T) {
	tools := os.Getenv("ONYX_TEST_TOOLS")
	avbtool := os.Getenv("ONYX_TEST_AVBTOOL")
	if tools == "" || avbtool == "" {
		t.Skip("set ONYX_TEST_TOOLS and ONYX_TEST_AVBTOOL to the checked image utilities")
	}
	p, old := retirementFixture(t)
	p.Compression = "lz4hc,level=12"
	root := t.TempDir()
	tree := &imageTree{FS: filesystem{UUID: "00112233445566778899aabbccddeeff", Label: hex.EncodeToString([]byte("retirement\x00\x00\x00\x00\x00\x00")), BlockSize: 4096}, Entries: make(map[string]*entry)}
	add := func(name string, mode uint32, data []byte) {
		t.Helper()
		meta := inode{PathHex: hex.EncodeToString([]byte(name)), NID: uint64(len(tree.Entries) + 1), Mode: mode,
			UID: 1001, GID: 3003, Size: uint64(len(data)), Mtime: 1793923200, MtimeNsec: 123450000,
			Xattrs: map[string]string{hex.EncodeToString([]byte("user.fixture")): hex.EncodeToString([]byte("retained\x00\xff"))}}
		node := &entry{Meta: meta}
		if mode&0170000 == 0100000 {
			path := filepath.Join(root, fmt.Sprintf("file_%d", meta.NID))
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			node.Source, node.Digest = path, ""
			node.Digest, _ = fileSHA(path)
		}
		tree.Entries[name] = node
	}
	for _, name := range []string{"", "lib", "lib/modules", "etc"} {
		add(name, 0040755, nil)
	}
	add("lib/modules/driver.ko", 0100644, []byte("original ordinary driver"))
	add("lib/modules/susfs_guard_lkm.ko", 0100644, old.Data["susfs_guard_lkm.ko"])
	for file, contents := range old.Config {
		add("lib/modules/"+file, 0100644, contents)
	}
	add("etc/rom.rc", 0100600, []byte("ROM service\x00\xff"))
	original := filepath.Join(root, "original.erofs")
	if err := writeEROFS(tools, tree, original, root, p.Compression); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("python3", avbtool, "add_hashtree_footer", "--image", original,
		"--partition_name", "vendor_dlkm", "--partition_size", "4194304", "--algorithm", "NONE",
		"--hash_algorithm", "sha256", "--salt", "11223344", "--do_not_generate_fec").CombinedOutput(); err != nil {
		t.Fatalf("independent AVB fixture: %v: %s", err, out)
	}
	updated := filepath.Join(root, "vendor_dlkm.img")
	if err := p.rebuildDLKM(tools, "vendor_dlkm", original, updated, filepath.Join(root, "rebuild")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("python3", avbtool, "verify_image", "--image", updated).CombinedOutput(); err != nil {
		t.Fatalf("independent AVB verification: %v: %s", err, out)
	}
	decoded, err := readEROFS(tools, updated, filepath.Join(root, "verify"))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := decoded.Entries["lib/modules/susfs_guard_lkm.ko"]; exists {
		t.Fatal("retired module survived image reconstruction")
	}
	for _, module := range p.Modules {
		node := decoded.Entries["lib/modules/"+module.File]
		if node == nil {
			t.Fatalf("ordinary module missing from rebuilt image: %s", module.File)
		}
		got, _ := os.ReadFile(node.Source)
		want, _ := os.ReadFile(filepath.Join(p.Root, "payload/modules", module.File))
		if !bytes.Equal(got, want) {
			t.Fatalf("ordinary module bytes changed: %s", module.File)
		}
	}
	before, after := tree.Entries["etc/rom.rc"], decoded.Entries["etc/rom.rc"]
	if after == nil || before.Digest != after.Digest || before.Meta.Mode != after.Meta.Mode || before.Meta.UID != after.Meta.UID || before.Meta.GID != after.Meta.GID ||
		before.Meta.Mtime != after.Meta.Mtime || before.Meta.MtimeNsec != after.Meta.MtimeNsec || !reflect.DeepEqual(before.Meta.Xattrs, after.Meta.Xattrs) {
		t.Fatal("unrelated ROM file data or metadata changed")
	}
}
