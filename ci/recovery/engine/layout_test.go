// SPDX-License-Identifier: GPL-2.0-only
package main

import (
	"crypto/sha256"
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
		{"active not updated", func(a, _ *lpPartition, _, _ *uint32) { a.Attributes = 1 }, false},
		{"other not updated", func(_, b *lpPartition, _, _ *uint32) { b.Attributes = 1 }, false},
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
