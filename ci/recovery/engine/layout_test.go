// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExactDLKMAlias(t *testing.T) {
	active := lpPartition{Name: "system_dlkm_b", Attributes: 5, Extents: []lpExtent{{100, 10, 0}, {200, 8, 10}}}
	other := lpPartition{Name: "system_dlkm_a", Attributes: 5, Extents: []lpExtent{{100, 10, 0}, {200, 8, 10}}}
	cases := []struct {
		name   string
		change func(*lpPartition, *lpPartition, *uint32, *uint32)
		want   bool
	}{
		{"identical", func(_, _ *lpPartition, _, _ *uint32) {}, true},
		{"disjoint inactive tail", func(_, b *lpPartition, _, _ *uint32) { b.Extents = append(b.Extents, lpExtent{300, 8, 18}) }, true},
		{"disjoint active tail", func(a, _ *lpPartition, _, _ *uint32) { a.Extents = append(a.Extents, lpExtent{300, 8, 18}) }, true},
		{"reverse slot", func(a, b *lpPartition, _, _ *uint32) { a.Name, b.Name = b.Name, a.Name }, true},
		{"resolved slot suffix attribute", func(a, b *lpPartition, _, _ *uint32) { a.Attributes, b.Attributes = 7, 7 }, true},
		{"not Virtual AB", func(_, _ *lpPartition, a, _ *uint32) { *a = 0 }, false},
		{"other not Virtual AB", func(_, _ *lpPartition, _, b *uint32) { *b = 0 }, false},
		{"disabled attribute", func(_, b *lpPartition, _, _ *uint32) { b.Attributes |= 8 }, false},
		{"other partition", func(_, b *lpPartition, _, _ *uint32) { b.Name = "vendor_dlkm_a" }, false},
		{"same slot", func(a, b *lpPartition, _, _ *uint32) { b.Name = a.Name }, false},
		{"non DLKM", func(a, b *lpPartition, _, _ *uint32) { a.Name, b.Name = "vendor_b", "vendor_a" }, false},
		{"partial physical overlap", func(_, b *lpPartition, _, _ *uint32) { b.Extents[0].Start++ }, false},
		{"different extent size", func(_, b *lpPartition, _, _ *uint32) { b.Extents[0].Count-- }, false},
		{"shorter inactive exact prefix", func(_, b *lpPartition, _, _ *uint32) { b.Extents = b.Extents[:1] }, true},
		{"empty active extents", func(a, _ *lpPartition, _, _ *uint32) { a.Extents = nil }, false},
		{"empty inactive extents", func(_, b *lpPartition, _, _ *uint32) { b.Extents = nil }, false},
		{"shifted logical offset", func(_, b *lpPartition, _, _ *uint32) { b.Extents[0].Logical++ }, false},
		{"active zero extent gap", func(a, b *lpPartition, _, _ *uint32) { a.Extents[1].Logical++; b.Extents[1].Logical++ }, false},
		{"inactive tail aliases active", func(_, b *lpPartition, _, _ *uint32) { b.Extents = append(b.Extents, lpExtent{105, 4, 18}) }, false},
		{"inactive tail before active end", func(_, b *lpPartition, _, _ *uint32) { b.Extents = append(b.Extents, lpExtent{300, 4, 17}) }, false},
		{"active tail aliases inactive", func(a, _ *lpPartition, _, _ *uint32) { a.Extents = append(a.Extents, lpExtent{105, 4, 18}) }, false},
		{"active tail before inactive end", func(a, _ *lpPartition, _, _ *uint32) { a.Extents = append(a.Extents, lpExtent{300, 4, 17}) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := active, other
			a.Extents, b.Extents = append([]lpExtent{}, active.Extents...), append([]lpExtent{}, other.Extents...)
			var af, bf uint32 = 1, 1
			tc.change(&a, &b, &af, &bf)
			if got := exactDLKMAlias(a, b, af, bf); got != tc.want {
				t.Fatalf("exactDLKMAlias = %t, want %t", got, tc.want)
			}
			if got := exactDLKMAlias(b, a, bf, af); got != tc.want {
				t.Fatalf("reversed exactDLKMAlias = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestExactDLKMAliasAttributes(t *testing.T) {
	cases := []struct {
		name               string
		active, other      uint32
		want, wantReversed bool
	}{
		{"both updated", 5, 5, true, true},
		{"updated target readonly source", 5, 1, true, false},
		{"resolved suffix attributes", 7, 3, true, false},
		{"readonly target updated source", 1, 5, false, true},
		{"both readonly only", 1, 1, false, false},
		{"target not readonly", 4, 5, false, false},
		{"source not readonly", 5, 4, false, false},
		{"disabled target", 13, 5, false, false},
		{"disabled source", 5, 9, false, false},
		{"unknown target attribute", 21, 5, false, false},
		{"unknown source attribute", 5, 17, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := lpPartition{Name: "vendor_dlkm_a", Attributes: tc.active, Extents: []lpExtent{{100, 10, 0}}}
			b := lpPartition{Name: "vendor_dlkm_b", Attributes: tc.other, Extents: []lpExtent{{100, 10, 0}}}
			if got := exactDLKMAlias(a, b, 1, 1); got != tc.want {
				t.Fatalf("exactDLKMAlias = %t, want %t", got, tc.want)
			}
			if got := exactDLKMAlias(b, a, 1, 1); got != tc.wantReversed {
				t.Fatalf("reversed exactDLKMAlias = %t, want %t", got, tc.wantReversed)
			}
		})
	}
}

func TestDLKMAliasUsesLogicalSectorsNotExtentBoundaries(t *testing.T) {
	cases := []struct {
		name string
		a, b []lpExtent
		want bool
	}{
		{"resized final extent", []lpExtent{{100, 10, 0}, {200, 4, 10}}, []lpExtent{{100, 10, 0}, {200, 12, 10}}, true},
		{"coalesced extent", []lpExtent{{100, 10, 0}, {110, 4, 10}}, []lpExtent{{100, 20, 0}}, true},
		{"split within shorter final extent", []lpExtent{{100, 14, 0}}, []lpExtent{{100, 10, 0}, {110, 10, 10}}, true},
		{"shifted shared sector", []lpExtent{{100, 10, 0}, {200, 4, 10}}, []lpExtent{{100, 10, 0}, {201, 12, 10}}, false},
		{"logical gap", []lpExtent{{100, 10, 0}}, []lpExtent{{100, 10, 0}, {200, 4, 11}}, false},
		{"tail reuses shared prefix", []lpExtent{{100, 10, 0}}, []lpExtent{{100, 10, 0}, {105, 4, 10}}, false},
		{"tail overlaps another tail extent", []lpExtent{{100, 10, 0}}, []lpExtent{{100, 10, 0}, {200, 4, 10}, {202, 4, 14}}, false},
		{"zero length extent", []lpExtent{{100, 10, 0}}, []lpExtent{{100, 10, 0}, {200, 0, 10}}, false},
		{"physical overflow", []lpExtent{{100, 10, 0}}, []lpExtent{{100, 10, 0}, {^uint64(0), 4, 10}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := lpPartition{Name: "vendor_dlkm_a", Attributes: 5, Extents: tc.a}
			b := lpPartition{Name: "vendor_dlkm_b", Attributes: 5, Extents: tc.b}
			if got := exactDLKMAlias(a, b, 1, 1); got != tc.want {
				t.Fatalf("alias = %t, want %t", got, tc.want)
			}
			if got := exactDLKMAlias(b, a, 1, 1); got != tc.want {
				t.Fatalf("reverse alias = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCompletedOnyxOTAMetadata(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "super.img")
	if err := os.WriteFile(path, golden(t, "onyx-ota-metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := readLP(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{"system_dlkm", "vendor_dlkm"} {
		var text strings.Builder
		fmt.Fprintf(&text, "Mapping: %s_a 254:3 event=0 uuid=\n", base)
		for _, part := range metadata.Partitions {
			if part.Name != base+"_a" {
				continue
			}
			for _, extent := range part.Extents {
				fmt.Fprintf(&text, "%d %d linear 259:17 %d\n", extent.Logical, extent.Count, extent.Start)
			}
		}
		if err := os.WriteFile(filepath.Join(root, base+"-map.txt"), []byte(text.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkLayout(path, "_a", root); err != nil {
		t.Fatal(err)
	}
	// The same real metadata must still reject an altered live mapping.
	mapPath := filepath.Join(root, "vendor_dlkm-map.txt")
	text, _ := os.ReadFile(mapPath)
	text = []byte(strings.Replace(string(text), "21469208", "21469209", 1))
	if err := os.WriteFile(mapPath, text, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkLayout(path, "_a", root); err == nil || !strings.Contains(err.Error(), "mapping differs") {
		t.Fatalf("accepted changed mapping: %v", err)
	}
}

func TestInactiveROMRecordEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*lpPartition, *lpMetadata, *lpMetadata)
		want   bool
	}{
		{"completed target", func(_ *lpPartition, _, _ *lpMetadata) {}, true},
		{"readonly source", func(o *lpPartition, _, _ *lpMetadata) { o.Attributes = 1 }, true},
		{"non Virtual AB", func(_ *lpPartition, a, _ *lpMetadata) { a.HeaderFlags = 0 }, false},
		{"disabled record", func(o *lpPartition, _, _ *lpMetadata) { o.Attributes |= 8 }, false},
		{"unflagged record", func(o *lpPartition, _, _ *lpMetadata) { o.Attributes = 0 }, false},
		{"non ROM partition", func(o *lpPartition, _, _ *lpMetadata) { o.Name = "userdata_b" }, false},
		{"DLKM partial alias", func(o *lpPartition, _, _ *lpMetadata) { o.Name = "vendor_dlkm_b" }, false},
		{"active slot record", func(o *lpPartition, _, _ *lpMetadata) { o.Name = "vendor_a" }, false},
		{"present in selected table", func(o *lpPartition, a, _ *lpMetadata) { a.Partitions = append(a.Partitions, *o) }, false},
		{"missing updated peer", func(_ *lpPartition, a, _ *lpMetadata) { a.Partitions = nil }, false},
		{"peer not updated", func(_ *lpPartition, a, _ *lpMetadata) { a.Partitions[0].Attributes = 1 }, false},
		{"unmatched group", func(o *lpPartition, _, _ *lpMetadata) { o.Group = "other_b" }, false},
		{"unmatched group flags", func(o *lpPartition, _, _ *lpMetadata) { o.GroupFlags = 1 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := lpPartition{Name: "vendor_b", Attributes: 5, Group: "qti_b", Extents: []lpExtent{{100, 10, 0}}}
			a := lpMetadata{HeaderFlags: 1, Partitions: []lpPartition{{Name: "vendor_a", Attributes: 5, Group: "qti_a", Extents: []lpExtent{{200, 10, 0}}}}}
			b := lpMetadata{HeaderFlags: 1}
			tc.change(&o, &a, &b)
			if _, got := inactiveROMPartition(o, &a, &b, "_a"); got != tc.want {
				t.Fatalf("inactive record = %t, want %t", got, tc.want)
			}
		})
	}
	for _, base := range []string{"system", "system_ext", "vendor", "product", "odm"} {
		for _, slot := range []string{"_a", "_b"} {
			opposite := "_b"
			if slot == "_b" {
				opposite = "_a"
			}
			o := lpPartition{Name: base + opposite, Attributes: 5, Group: "qti" + opposite, Extents: []lpExtent{{100, 10, 0}}}
			a := lpMetadata{HeaderFlags: 1, Partitions: []lpPartition{{Name: base + slot, Attributes: 5, Group: "qti" + slot, Extents: []lpExtent{{200, 10, 0}}}}}
			b := lpMetadata{HeaderFlags: 1}
			if _, ok := inactiveROMPartition(o, &a, &b, slot); !ok {
				t.Fatalf("rejected %s with active slot %s", base, slot)
			}
		}
	}
}

func TestInactiveROMRuntimeEvidence(t *testing.T) {
	for _, base := range []string{"vendor", "system_ext"} {
		for _, extra := range []string{"", base + "_b", base + "_b-base", base + "_b-cow", "missing-peer"} {
			names := []string{"vendor_dlkm_a", "system_dlkm_a", base + "_a"}
			if extra == "missing-peer" {
				names = names[:2]
			} else if extra != "" {
				names = append(names, extra)
			}
			err := checkDormantAllocationRuntime([]dormantAllocation{{base + "_b", base + "_b"}}, func() error { return nil }, func() ([]string, error) { return names, nil })
			if (err == nil) != (extra == "") {
				t.Fatalf("%s runtime names %v: %v", base, names, err)
			}
		}
	}
}

func TestStaleInactiveROMOverlapsUseSelectedTableAndRuntime(t *testing.T) {
	for _, pair := range [][2]string{{"vendor_dlkm", "vendor"}, {"system_dlkm", "system_ext"}} {
		data := golden(t, "onyx-ota-metadata")
		maximum, count := int(le.Uint32(data[4136:])), int(le.Uint32(data[4140:]))
		// Keep the selected table byte-for-byte unchanged. In the old table,
		// move the DLKM allocation into the old ROM partition's vacated range
		// and leave its old ROM record over blocks now owned by active DLKM.
		for _, offset := range []int{12288 + maximum, 12288 + (count+1)*maximum} {
			h := data[offset : offset+maximum]
			hs, ts := int(le.Uint32(h[8:])), int(le.Uint32(h[44:]))
			tables := h[hs : hs+ts]
			parts, extents := int(le.Uint32(h[80:])), int(le.Uint32(h[92:]))
			var oldROM, oldDLKM []byte
			for i := 0; i < int(le.Uint32(h[84:])); i++ {
				row := tables[parts+i*52 : parts+(i+1)*52]
				name, _ := nullString(row[:36])
				if name == pair[1]+"_b" {
					oldROM = row
				}
				if name == pair[0]+"_b" {
					oldDLKM = row
				}
			}
			if oldROM == nil || oldDLKM == nil {
				t.Fatal("missing source fixture partitions")
			}
			romExtent := tables[extents+int(le.Uint32(oldROM[40:]))*24:]
			dlkmFirst := int(le.Uint32(oldDLKM[40:]))
			romStart := le.Uint64(romExtent[12:])
			dlkmStart := le.Uint64(tables[extents+dlkmFirst*24+12:])
			le.PutUint64(romExtent, 8)
			le.PutUint64(romExtent[12:], dlkmStart)
			for i := 0; i < int(le.Uint32(oldDLKM[44:])); i++ {
				e := tables[extents+(dlkmFirst+i)*24:]
				le.PutUint64(e[12:], romStart)
				romStart += le.Uint64(e)
			}
			sum := sha256.Sum256(tables)
			copy(h[48:80], sum[:])
			clear(h[12:44])
			sum = sha256.Sum256(h[:hs])
			copy(h[12:44], sum[:])
		}
		root := t.TempDir()
		path := filepath.Join(root, "super.img")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		active, err := readLP(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range active.Partitions {
			base := strings.TrimSuffix(part.Name, "_a")
			if base != "vendor_dlkm" && base != "system_dlkm" {
				continue
			}
			var text strings.Builder
			fmt.Fprintf(&text, "Mapping: %s 254:3 event=0 uuid=\n", part.Name)
			for _, e := range part.Extents {
				fmt.Fprintf(&text, "%d %d linear 259:17 %d\n", e.Logical, e.Count, e.Start)
			}
			if err := os.WriteFile(filepath.Join(root, base+"-map.txt"), []byte(text.String()), 0600); err != nil {
				t.Fatal(err)
			}
		}
		for _, mode := range []string{"clean", "live-inactive", "pending-snapshot", "no-verifier"} {
			called := false
			verify := func(records []dormantAllocation) error {
				called = true
				if len(records) != 1 || records[0].Name != pair[1]+"_b" {
					t.Fatalf("unexpected records %v", records)
				}
				return checkDormantAllocationRuntime(records, func() error {
					if mode == "pending-snapshot" {
						return errors.New("pending snapshot")
					}
					return nil
				}, func() ([]string, error) {
					names := []string{"vendor_dlkm_a", "system_dlkm_a", pair[1] + "_a"}
					if mode == "live-inactive" {
						names = append(names, pair[1]+"_b")
					}
					return names, nil
				})
			}
			if mode == "no-verifier" {
				verify = nil
			}
			err := checkLayoutWithRuntime(path, "_a", root, verify)
			if (err == nil) != (mode == "clean") || (mode != "no-verifier" && !called) {
				t.Fatalf("%v %s: called=%t error=%v", pair, mode, called, err)
			}
		}
	}
}

func rewriteLPFixture(data []byte, change func([]byte, []byte, int, int)) {
	for _, offset := range []int{12288, 12288 + 65536, 12288 + 2*65536, 12288 + 3*65536} {
		header := data[offset : offset+65536]
		hsize, tsize := int(le.Uint32(header[8:])), int(le.Uint32(header[44:]))
		parts, extents := int(le.Uint32(header[80:])), int(le.Uint32(header[92:]))
		change(header, header[hsize:hsize+tsize], parts, extents)
		tsize = int(le.Uint32(header[44:]))
		sum := sha256.Sum256(header[hsize : hsize+tsize])
		copy(header[48:80], sum[:])
		clear(header[12:44])
		sum = sha256.Sum256(header[:hsize])
		copy(header[12:44], sum[:])
	}
}

func TestLibLPExactAliasAndMappingGuards(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "super.img")
	data := golden(t, "liblp-metadata")
	rewriteLPFixture(data, func(_ []byte, tables []byte, parts, extents int) {
		le.PutUint32(tables[parts+36:], 5)
		le.PutUint32(tables[parts+2*52+36:], 5)
		le.PutUint64(tables[extents+2*24+12:], 2048)
	})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := readLP(path, 0)
	if err != nil || metadata.HeaderFlags != 1 || metadata.Partitions[0].Attributes != 5 {
		t.Fatalf("lost alias metadata evidence: %v, %v", metadata, err)
	}
	for _, slot := range []string{"_a", "_b"} {
		for _, name := range []string{"vendor_dlkm", "system_dlkm"} {
			physical := 2048
			if name == "system_dlkm" {
				physical = 6144
				if slot == "_b" {
					physical = 14336
				}
			}
			text := fmt.Sprintf("Mapping: %s%s 253:7 event=0 uuid=\n0 4096 linear 8:1 %d\n", name, slot, physical)
			if err := os.WriteFile(filepath.Join(root, name+"-map.txt"), []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := checkLayout(path, slot, root); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "vendor_dlkm-map.txt"), []byte("Mapping: vendor_dlkm_b 253:7 event=0 uuid=\n0 4096 linear 8:1 2049\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkLayout(path, "_b", root); err == nil || !strings.Contains(err.Error(), "mapping differs") {
		t.Fatalf("accepted alias with mismatched active mapper: %v", err)
	}
	// An exact counterpart must not make sharing with a third partition safe.
	rewriteLPFixture(data, func(_ []byte, tables []byte, _, extents int) { le.PutUint64(tables[extents+3*24+12:], 2048) })
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkLayout(path, "_a", root); err == nil || !strings.Contains(err.Error(), "shares physical data with system_dlkm_b") {
		t.Fatalf("accepted non-counterpart sharing: %v", err)
	}
}

func dlkmPrefixFixture(t *testing.T, tail uint64) []byte {
	t.Helper()
	data := golden(t, "liblp-metadata")
	rewriteLPFixture(data, func(header, tables []byte, parts, extents int) {
		// Add a two-extent vendor_dlkm_a after the four original extents;
		// vendor_dlkm_b contains only its exact first extent.
		hsize, tsize := int(le.Uint32(header[8:])), len(tables)
		end := extents + int(le.Uint32(header[96:]))*24
		expanded := header[hsize : hsize+tsize+48]
		copy(expanded[end+48:], expanded[end:tsize])
		copy(expanded[end:end+24], tables[extents:extents+24])
		clear(expanded[end+24 : end+48])
		le.PutUint64(expanded[end+24:], 1024)
		le.PutUint64(expanded[end+24+12:], tail)
		le.PutUint32(header[96:], 6)
		le.PutUint32(header[104:], le.Uint32(header[104:])+48)
		le.PutUint32(header[116:], le.Uint32(header[116:])+48)
		le.PutUint32(header[44:], uint32(tsize+48))
		le.PutUint32(tables[parts+36:], 5)
		le.PutUint32(tables[parts+40:], 4)
		le.PutUint32(tables[parts+44:], 2)
		le.PutUint32(tables[parts+2*52+36:], 5)
		le.PutUint64(tables[extents+2*24+12:], 2048)
	})
	return data
}

func TestLibLPSymmetricPrefixGuards(t *testing.T) {
	cases := []struct {
		name, slot, wantError string
		tail                  uint64
		badMap                bool
	}{
		{"disjoint active tail", "_a", "", 24000, false},
		{"disjoint inactive tail", "_b", "", 24000, false},
		{"active tail overlaps prefix", "_a", "overlaps itself", 2050, false},
		{"inactive tail overlaps prefix", "_b", "shares physical data", 2050, false},
		{"active tail overlaps unrelated partition", "_a", "shares physical data with system_dlkm_b", 14336, false},
		{"changed active tail mapping", "_a", "mapping differs", 24000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "super.img")
			if err := os.WriteFile(path, dlkmPrefixFixture(t, tc.tail), 0600); err != nil {
				t.Fatal(err)
			}
			vendor := fmt.Sprintf("Mapping: vendor_dlkm%s 253:7 event=0 uuid=\n0 4096 linear 8:1 2048\n", tc.slot)
			systemPhysical := 14336
			if tc.slot == "_a" {
				tail := tc.tail
				if tc.badMap {
					tail++
				}
				vendor += fmt.Sprintf("4096 1024 linear 8:1 %d\n", tail)
				systemPhysical = 6144
			}
			system := fmt.Sprintf("Mapping: system_dlkm%s 253:8 event=0 uuid=\n0 4096 linear 8:1 %d\n", tc.slot, systemPhysical)
			for name, text := range map[string]string{"vendor_dlkm": vendor, "system_dlkm": system} {
				if err := os.WriteFile(filepath.Join(root, name+"-map.txt"), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := checkLayout(path, tc.slot, root)
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("checkLayout = %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestLibLPUpdatedTargetReadonlySource(t *testing.T) {
	cases := []struct {
		name, slot, wantError string
		target, source        uint32
		tail                  uint64
		badMap, shiftedSource bool
	}{
		{"slot a updated target readonly source", "_a", "", 5, 1, 24000, false, false},
		{"slot b updated target readonly source", "_b", "", 5, 1, 24000, false, false},
		{"both readonly only", "_a", "shares physical data", 1, 1, 24000, false, false},
		{"readonly target updated source", "_a", "shares physical data", 1, 5, 24000, false, false},
		{"source not readonly", "_a", "shares physical data", 5, 4, 24000, false, false},
		{"disabled source", "_a", "shares physical data", 5, 9, 24000, false, false},
		{"shifted source physical extent", "_a", "shares physical data", 5, 1, 24000, false, true},
		{"active tail overlaps prefix", "_a", "overlaps itself", 5, 1, 2050, false, false},
		{"active tail overlaps unrelated partition", "_a", "shares physical data with system_dlkm_b", 5, 1, 14336, false, false},
		{"changed active mapping", "_a", "mapping differs", 5, 1, 24000, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "super.img")
			data := dlkmPrefixFixture(t, tc.tail)
			rewriteLPFixture(data, func(header, tables []byte, parts, extents int) {
				for _, i := range []int{0, 2} {
					row := tables[parts+i*52 : parts+(i+1)*52]
					name, err := nullString(row[:36])
					if err != nil {
						t.Fatal(err)
					}
					attributes := tc.source
					if name == "vendor_dlkm"+tc.slot {
						attributes = tc.target
					} else if tc.shiftedSource {
						offset := extents + int(le.Uint32(row[40:]))*24
						le.PutUint64(tables[offset+12:], le.Uint64(tables[offset+12:])+1)
					}
					le.PutUint32(row[36:], attributes)
				}
			})
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			physical := uint64(2048)
			if tc.badMap {
				physical++
			}
			vendor := fmt.Sprintf("Mapping: vendor_dlkm%s 253:7 event=0 uuid=\n0 4096 linear 8:1 %d\n", tc.slot, physical)
			systemPhysical := 14336
			if tc.slot == "_a" {
				vendor += fmt.Sprintf("4096 1024 linear 8:1 %d\n", tc.tail)
				systemPhysical = 6144
			}
			system := fmt.Sprintf("Mapping: system_dlkm%s 253:8 event=0 uuid=\n0 4096 linear 8:1 %d\n", tc.slot, systemPhysical)
			for name, text := range map[string]string{"vendor_dlkm": vendor, "system_dlkm": system} {
				if err := os.WriteFile(filepath.Join(root, name+"-map.txt"), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := checkLayout(path, tc.slot, root)
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("checkLayout = %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestInactiveCOWMetadataEvidence(t *testing.T) {
	cases := []struct {
		name   string
		change func(*lpPartition, *lpMetadata, *lpMetadata)
		want   bool
	}{
		{"dormant opposite allocation", func(_ *lpPartition, _, _ *lpMetadata) {}, true},
		{"name alone outside cow group", func(c *lpPartition, _, _ *lpMetadata) { c.Group = "default" }, false},
		{"suffix flagged cow group", func(c *lpPartition, _, _ *lpMetadata) { c.GroupFlags = 1 }, false},
		{"nonzero cow attributes", func(c *lpPartition, _, _ *lpMetadata) { c.Attributes = 1 }, false},
		{"same slot cow", func(c *lpPartition, _, _ *lpMetadata) { c.Name = "odm_a-cow" }, false},
		{"missing cow suffix", func(c *lpPartition, _, _ *lpMetadata) { c.Name = "odm_b" }, false},
		{"missing parent", func(_ *lpPartition, _ *lpMetadata, i *lpMetadata) { i.Partitions = nil }, false},
		{"parent not updated", func(_ *lpPartition, _ *lpMetadata, i *lpMetadata) { i.Partitions[0].Attributes = 1 }, false},
		{"parent also cow group", func(_ *lpPartition, _ *lpMetadata, i *lpMetadata) { i.Partitions[0].Group = "cow" }, false},
		{"parent disabled", func(_ *lpPartition, _ *lpMetadata, i *lpMetadata) { i.Partitions[0].Attributes = 13 }, false},
		{"empty parent", func(_ *lpPartition, _ *lpMetadata, i *lpMetadata) { i.Partitions[0].Extents = nil }, false},
		{"cow still in active metadata", func(c *lpPartition, a, _ *lpMetadata) { a.Partitions = append(a.Partitions, *c) }, false},
		{"active not Virtual AB", func(_ *lpPartition, a, _ *lpMetadata) { a.HeaderFlags = 0 }, false},
		{"inactive not Virtual AB", func(_ *lpPartition, _ *lpMetadata, i *lpMetadata) { i.HeaderFlags = 0 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cow := lpPartition{Name: "odm_b-cow", Group: "cow", Extents: []lpExtent{{300, 20, 0}}}
			active := lpMetadata{HeaderFlags: 1, Partitions: []lpPartition{{Name: "odm_a", Attributes: 5, Group: "default", Extents: []lpExtent{{100, 10, 0}}}}}
			inactive := lpMetadata{HeaderFlags: 1, Partitions: []lpPartition{{Name: "odm_b", Attributes: 5, Group: "default", Extents: []lpExtent{{200, 10, 0}}}}}
			tc.change(&cow, &active, &inactive)
			got, allowed := inactiveCOW(cow, &active, &inactive, "_a")
			if allowed != tc.want {
				t.Fatalf("inactiveCOW = %t, want %t", allowed, tc.want)
			}
			if allowed && got != (dormantAllocation{"odm_b-cow", "odm_b"}) {
				t.Fatalf("unexpected dormant allocation identity: %v", got)
			}
		})
	}
	// The same evidence must work when slot B is selected.
	cow := lpPartition{Name: "odm_a-cow", Group: "cow"}
	active := lpMetadata{HeaderFlags: 1}
	inactive := lpMetadata{HeaderFlags: 1, Partitions: []lpPartition{{Name: "odm_a", Group: "default", Attributes: 5, Extents: []lpExtent{{200, 10, 0}}}}}
	if _, allowed := inactiveCOW(cow, &active, &inactive, "_b"); !allowed {
		t.Fatal("rejected dormant slot A allocation while slot B is active")
	}
}

func TestLibLPGroupIdentityValidation(t *testing.T) {
	cases := []struct {
		name, wantGroup string
		change          func([]byte)
		wantError       bool
	}{
		{"ordinary group", "default", func(_ []byte) {}, false},
		{"resolved group suffix", "default_a", func(group []byte) { le.PutUint32(group[36:], 1) }, false},
		{"invalid group name", "", func(group []byte) { group[0] = '/' }, true},
		{"invalid group padding", "", func(group []byte) { group[8] = 'x' }, true},
		{"unknown group flags", "", func(group []byte) { le.PutUint32(group[36:], 2) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := golden(t, "liblp-metadata")
			rewriteLPFixture(data, func(header, tables []byte, _, _ int) {
				offset := int(le.Uint32(header[104:]))
				tc.change(tables[offset : offset+48])
			})
			path := filepath.Join(t.TempDir(), "super.img")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			metadata, err := readLP(path, 0)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "invalid logical partition group") {
					t.Fatalf("readLP = %v, want invalid group", err)
				}
			} else if err != nil || metadata.Partitions[0].Group != tc.wantGroup {
				t.Fatalf("readLP group = %v, error = %v", metadata, err)
			}
		})
	}
}

func TestDormantCOWRuntimeEvidence(t *testing.T) {
	cases := []struct {
		name            string
		extraNames      []string
		noMappings      bool
		snapshotFailure int
		listFailure     bool
		wantError       string
	}{
		{"clean current slot cow", []string{"odm_a-cow"}, false, 0, false, ""},
		{"unrelated similar name", []string{"odm_blah"}, false, 0, false, ""},
		{"live old cow", []string{"odm_b-cow"}, false, 0, false, "live mapping"},
		{"live inactive parent", []string{"odm_b"}, false, 0, false, "live mapping"},
		{"related snapshot mapping", []string{"odm_b-base"}, false, 0, false, "live mapping"},
		{"unknown mapping name", []string{"odm_b-cow\n"}, false, 0, false, "invalid live"},
		{"empty mapper enumeration", nil, true, 0, false, "missing active partition"},
		{"snapshot not clean", nil, false, 1, false, "snapshot state"},
		{"snapshot changes during enumeration", nil, false, 2, false, "snapshot state changed"},
		{"mapper enumeration failure", nil, false, 0, true, "cannot enumerate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshotCalls := 0
			snapshot := func() error {
				snapshotCalls++
				if snapshotCalls == tc.snapshotFailure {
					return errors.New("snapshot state is not clean")
				}
				return nil
			}
			live := func() ([]string, error) {
				if tc.listFailure {
					return nil, errors.New("unreadable sysfs")
				}
				if tc.noMappings {
					return nil, nil
				}
				return append([]string{"vendor_dlkm_a", "system_dlkm_a"}, tc.extraNames...), nil
			}
			err := checkDormantAllocationRuntime([]dormantAllocation{{"odm_b-cow", "odm_b"}}, snapshot, live)
			if tc.wantError == "" {
				if err != nil || snapshotCalls != 2 {
					t.Fatalf("runtime proof: %v, snapshot calls %d", err, snapshotCalls)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("runtime proof = %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestCapturedLayoutDormantCOW(t *testing.T) {
	// An optional external capture binds this test to real read-only metadata.
	// This test-only input never changes the production executable's checks.
	capture := os.Getenv("ONYX_LAYOUT_TEST_CAPTURE")
	if capture == "" {
		t.Skip("no external Onyx recovery layout capture supplied")
	}
	root := t.TempDir()
	for _, name := range []string{"vendor_dlkm", "system_dlkm"} {
		data, err := os.ReadFile(filepath.Join(capture, name+"-map.stdout"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name+"-map.txt"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, wantError string
		liveCow         bool
		snapshotError   bool
	}{
		{"captured completed layout", "", false, false},
		{"captured layout with live old cow", "live mapping", true, false},
		{"captured layout with pending snapshot", "snapshot state", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			verify := func(cows []dormantAllocation) error {
				called = true
				if len(cows) != 1 || cows[0] != (dormantAllocation{"odm_b-cow", "odm_b"}) {
					t.Fatalf("unexpected captured dormant COW identity: %v", cows)
				}
				return checkDormantAllocationRuntime(cows, func() error {
					if tc.snapshotError {
						return errors.New("pending snapshot")
					}
					return nil
				}, func() ([]string, error) {
					names := []string{"vendor_dlkm_a", "system_dlkm_a", "odm_a-cow"}
					if tc.liveCow {
						names = append(names, "odm_b-cow")
					}
					return names, nil
				})
			}
			err := checkLayoutWithRuntime(filepath.Join(capture, "super-metadata.stdout"), "_a", root, verify)
			if !called {
				t.Fatalf("captured dormant COW path was not verified: %v", err)
			}
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("captured layout = %v, want error containing %q", err, tc.wantError)
			}
		})
	}
}

func TestLibLPPreservesLogicalOffsetAfterZeroExtent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "super.img")
	data := golden(t, "liblp-metadata")
	rewriteLPFixture(data, func(_ []byte, tables []byte, parts, extents int) {
		le.PutUint32(tables[parts+2*52+44:], 2)
		le.PutUint32(tables[extents+2*24+8:], 1)
	})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := readLP(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	partition := metadata.Partitions[2]
	if len(partition.Extents) != 1 || partition.Extents[0].Logical != 4096 {
		t.Fatalf("zero extent lost logical offset: %+v", partition)
	}
}
