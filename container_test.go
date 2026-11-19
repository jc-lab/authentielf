package authentielf

import (
	"bytes"
	"crypto"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jc-lab/authentielf/internal/testpki"
)

// The full matrix (static/dynamic, PIE/non-PIE, shared libraries, many
// architectures under qemu) lives in test/e2e.sh (make e2e). These tests
// cover the container format itself with what the host can build.

func buildGo(t *testing.T, goarch, src string) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "m.go")
	os.WriteFile(path, []byte(src), 0o644)
	out := filepath.Join(dir, "bin")
	cmd := exec.Command("go", "build", "-o", out, path)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", goarch, err, b)
	}
	d, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func signContainer(t *testing.T, data []byte) []byte {
	t.Helper()
	p := testpki.New(t, "ecdsa")
	return signWith(t, data, p.Leaf, p, crypto.SHA256, false, nil)
}

// checkStructure validates the signed file with debug/elf (an independent
// parser) and checks the invariants of the format.
func checkStructure(t *testing.T, signed, orig []byte) {
	t.Helper()
	ef, err := elf.NewFile(bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("debug/elf rejects signed file: %v", err)
	}
	defer ef.Close()
	sec, note := ef.Section(SectionName), ef.Section(NoteSectionName)
	if sec == nil || note == nil || sec.Flags&elf.SHF_ALLOC == 0 || note.Type != elf.SHT_NOTE {
		t.Fatalf("sections missing or wrong: %+v %+v", sec, note)
	}
	var load, aelf *elf.Prog
	for _, p := range ef.Progs {
		switch {
		case p.Type == elf.PT_LOAD && p.Off <= sec.Offset && sec.Offset+sec.Size <= p.Off+p.Filesz:
			load = p
		case p.Type == PT_AUTHENTIELF:
			aelf = p
		}
	}
	if load == nil || load.Flags != elf.PF_R || aelf == nil || aelf.Vaddr != sec.Addr || aelf.Filesz != sec.Size {
		t.Fatalf("segments wrong: load=%+v aelf=%+v", load, aelf)
	}
	if load.Vaddr%load.Align != load.Off%load.Align {
		t.Fatal("PT_LOAD offset/vaddr not congruent")
	}
	if !bytes.Equal(signed[64:len(orig)], orig[64:]) {
		t.Fatal("original bytes after the ELF header were modified")
	}
	info, err := Inspect(signed)
	if err != nil {
		t.Fatal(err)
	}
	// Growth = padding + program headers + signature + note + string and
	// section header tables; no fixed-size reservation.
	overhead := uint64(len(signed)) - uint64(len(orig)) - info.Padding - info.SectionSize
	if overhead > 8192 {
		t.Fatalf("unexpected overhead of %d bytes", overhead)
	}
	if sec.Size > 64<<10 {
		t.Fatalf("section is %d bytes", sec.Size)
	}
}

func TestSignedBinariesRun(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("needs linux/amd64 to execute the binaries")
	}
	bins := map[string][]byte{
		"go-static": buildGo(t, "amd64", "package main\nfunc main() { println(\"hello authentielf\") }\n"),
	}
	if cc, err := exec.LookPath("cc"); err == nil {
		dir := t.TempDir()
		src := filepath.Join(dir, "hello.c")
		os.WriteFile(src, []byte("#include <stdio.h>\nint main(void){ puts(\"hello authentielf\"); return 0; }\n"), 0o644)
		for name, args := range map[string][]string{
			"c-pie": {"-fPIE", "-pie"}, "c-nopie": {"-fno-pie", "-no-pie"},
			"c-static": {"-static"}, "c-staticpie": {"-static-pie"},
		} {
			out := filepath.Join(dir, name)
			if b, err := exec.Command(cc, append(args, "-O2", "-o", out, src)...).CombinedOutput(); err != nil {
				t.Logf("skip %s: %v\n%s", name, err, b)
				continue
			}
			bins[name], _ = os.ReadFile(out)
		}
	}
	for name, orig := range bins {
		t.Run(name, func(t *testing.T) {
			signed := signContainer(t, orig)
			checkStructure(t, signed, orig)
			path := filepath.Join(t.TempDir(), name)
			os.WriteFile(path, signed, 0o755)
			out, err := exec.Command(path).CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte("hello authentielf")) {
				t.Fatalf("signed binary failed: %v %q", err, out)
			}
		})
	}
}

// TestCrossArch covers ELF32/ELF64 and little/big endian layouts.
func TestCrossArch(t *testing.T) {
	for _, arch := range []string{"386", "arm", "arm64", "ppc64", "mips", "riscv64", "s390x"} {
		t.Run(arch, func(t *testing.T) {
			orig := buildGo(t, arch, "package main\nfunc main() { println(\"cross\") }\n")
			signed := signContainer(t, orig)
			checkStructure(t, signed, orig)
			if back, err := Original(signed); err != nil || !bytes.Equal(back, orig) {
				t.Fatalf("original not restored: %v", err)
			}
		})
	}
}

// TestPlacement checks the choice between legacy-compatible and compact
// placement of the new segment.
func TestPlacement(t *testing.T) {
	small := signContainer(t, buildGo(t, "amd64", "package main\nfunc main() {}\n"))
	if info, _ := Inspect(small); !info.Legacy {
		t.Errorf("small bss: want legacy placement, got %+v", info)
	}
	// 64 MiB of bss that ends far beyond the end of the file: legacy
	// placement would need that much padding, so compact placement is used.
	orig := buildGo(t, "amd64", "package main\nvar big [64 << 20]byte\nfunc main() { big[1] = 1; println(big[1]) }\n")
	signed := signContainer(t, orig)
	info, err := Inspect(signed)
	if err != nil {
		t.Fatal(err)
	}
	if info.Legacy || info.Padding != 0 {
		t.Fatalf("big bss: want compact placement, got %+v", info)
	}
	if growth := len(signed) - len(orig); growth > 32<<10 {
		t.Fatalf("file grew by %d bytes", growth)
	}
	checkStructure(t, signed, orig)
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		path := filepath.Join(t.TempDir(), "bigbss")
		os.WriteFile(path, signed, 0o755)
		if out, err := exec.Command(path).CombinedOutput(); err != nil {
			t.Fatalf("run: %v %s", err, out)
		}
	}
}

// TestNoSectionHeaders covers files whose section header table was stripped
// (e.g. by sstrip): a new table is created, and removed again on unsign.
func TestNoSectionHeaders(t *testing.T) {
	orig := sampleELF(t)
	f, err := parseELF(orig)
	if err != nil {
		t.Fatal(err)
	}
	f.putHeaderTables(orig, f.hdr.Phoff, len(f.progs), 0, 0, 0)
	signed := signContainer(t, orig)
	ef, err := elf.NewFile(bytes.NewReader(signed))
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	if len(ef.Sections) != 4 || ef.Section(SectionName) == nil || ef.Section(".shstrtab") == nil {
		t.Fatalf("unexpected sections: %d", len(ef.Sections))
	}
	if back, err := Original(signed); err != nil || !bytes.Equal(back, orig) {
		t.Fatalf("original not restored: %v", err)
	}
}

func TestRejectSegmentPastEOF(t *testing.T) {
	orig := sampleELF(t)
	// Truncating the file leaves segments referencing bytes past its end;
	// after signing those bytes would be the unauthenticated tail.
	if _, err := WritePKCS7(orig[:len(orig)/2], []byte{0x30, 0}); err == nil {
		t.Fatal("accepted a file whose segments extend past its end")
	}
}
