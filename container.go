package authentielf

import (
	"bytes"
	"crypto"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// An AuthentiELF-signed file is a deterministic function of the original
// (unsigned) file and the PKCS#7 blob:
//
//	signed = layout(original, pkcs7)
//
// layout keeps every byte of the original in place, patches five ELF header
// fields and appends a tail:
//
//	[original file; e_phoff/e_phnum/e_shoff/e_shnum/e_shstrndx patched ]
//	[zero padding (legacy placement only, see below)                   ]
//	[new program header table   ] <- e_phoff, PT_PHDR   \ new read-only
//	[.authentielf: signature    ] <- PT_AUTHENTIELF     / PT_LOAD
//	[.note.authentielf          ]   original ELF header + size
//	[.shstrtab (old + 2 names)  ]
//	[section header table       ] <- e_shoff (old entries + 2)
//
// The note stores what the patch overwrote, so a verifier can rebuild the
// original, recompute layout(original, pkcs7) and require the file to be
// exactly that. Because layout has no free parameters, any change to the
// file other than replacing the PKCS#7 blob is detected, and the image
// digest is simply the hash of the original file — identical before and
// after signing, as with Authenticode.

const (
	// SectionName is the section holding the signature entry.
	SectionName = ".authentielf"
	// NoteSectionName is the section holding the original-file record.
	NoteSectionName = ".note.authentielf"
	// NoteName and NoteTypeOrigin identify the ELF note in NoteSectionName.
	NoteName       = "AuthentiELF"
	NoteTypeOrigin = 1

	// PT_AUTHENTIELF ("aelf", in PT_LOOS..PT_HIOS) points exactly at the
	// loaded .authentielf section so that a running program can find its
	// signature via dl_iterate_phdr/AT_PHDR; section headers are not loaded.
	PT_AUTHENTIELF elf.ProgType = 0x61656c66

	// EntryHeaderSize is the size of the [u32 length][u16 version] header
	// that precedes the PKCS#7 blob (cf. WIN_CERTIFICATE).
	EntryHeaderSize = 6
	// EntryVersion is the only defined entry version.
	EntryVersion = 1
	// MaxSectionSize is the maximum size of the .authentielf section.
	MaxSectionSize = 1 << 20
	// MaxPKCS7Size is the largest PKCS#7 blob that fits.
	MaxPKCS7Size = MaxSectionSize - EntryHeaderSize

	// MaxLegacyPadding bounds the zero padding layout may insert to keep the
	// new segment loadable by kernels older than 5.18 (see placement).
	MaxLegacyPadding = 256 << 10

	sectionAlign = 8 // like the PE certificate table: quadword aligned
	noteVersion  = 1
)

var (
	// ErrNotSigned means the file carries no AuthentiELF signature.
	ErrNotSigned = errors.New("authentielf: file is not signed")
	// ErrNotCanonical means the AuthentiELF structures are not exactly what
	// the original file and signature determine: the file was modified.
	ErrNotCanonical = errors.New("authentielf: file was modified after signing (layout is not canonical)")
)

// ContainerInfo describes the AuthentiELF structures of a signed file.
type ContainerInfo struct {
	OriginalSize  uint64 // size of the unsigned original
	SectionOffset uint64 // file offset of .authentielf
	SectionVaddr  uint64 // virtual address of .authentielf (relative to the load bias for ET_DYN)
	SectionSize   uint64
	Padding       uint64 // zero padding inserted for legacy-kernel placement
	Legacy        bool   // segment placed so that pre-5.18 kernels compute AT_PHDR correctly
}

// container is a parsed and validated signed file.
type container struct {
	original []byte
	pkcs7    []byte
	info     ContainerInfo
}

type elfLayout struct {
	hdr  []byte // patched ELF header (replaces original[:ehsize])
	tail []byte // appended after the original
	info ContainerInfo
}

func (l *elfLayout) assemble(original []byte) []byte {
	out := make([]byte, 0, len(original)+len(l.tail))
	out = append(out, l.hdr...)
	out = append(out, original[len(l.hdr):]...)
	return append(out, l.tail...)
}

// checkOriginal rejects inputs that layout cannot handle safely. In
// particular nothing in the original may reference file bytes past its end:
// after signing those bytes would be our (partly unauthenticated) tail.
func (f *elfFile) checkOriginal() error {
	if f.hdr.Type != elf.ET_EXEC && f.hdr.Type != elf.ET_DYN {
		return fmt.Errorf("authentielf: unsupported ELF type %v", f.hdr.Type)
	}
	n := len(f.data)
	for _, p := range f.progs {
		if p.Type == PT_AUTHENTIELF {
			return errors.New("authentielf: file already contains PT_AUTHENTIELF")
		}
		if p.Filesz > 0 && !rangeOK(p.Off, p.Filesz, n) {
			return fmt.Errorf("authentielf: %v segment extends past end of file", p.Type)
		}
	}
	for i, s := range f.sects {
		if name := f.sectionName(i); name == SectionName || name == NoteSectionName {
			return fmt.Errorf("authentielf: file already contains %s section", name)
		}
		if s.Type != elf.SHT_NOBITS && s.Size > 0 && !rangeOK(s.Off, s.Size, n) {
			return fmt.Errorf("authentielf: section %d extends past end of file", i)
		}
	}
	return nil
}

// placement chooses the file offset and virtual address of the new PT_LOAD
// (which starts with the new program header table).
//
// Kernels before 5.18 compute AT_PHDR as load_addr + e_phoff, where
// load_addr = vaddr - offset of the first PT_LOAD; glibc's ld.so and static
// glibc then read the program headers from there. Keeping
// vaddr - offset equal to that bias ("legacy placement") can require zero
// padding in the file when the memory image (bss) reaches beyond the end of
// the file. Legacy placement is used when possible with at most
// MaxLegacyPadding bytes of padding; otherwise the segment goes directly
// after the original with an independent vaddr (correct on kernels >= 5.18).
func (f *elfFile) placement(segAlign, maxVEnd uint64, firstLoad progHeader) (off, vaddr uint64, legacy bool) {
	base := alignUp(uint64(len(f.data)), sectionAlign)
	if fl := firstLoad; fl.Vaddr >= fl.Off && (fl.Vaddr-fl.Off)%segAlign == 0 {
		bias := fl.Vaddr - fl.Off
		need := uint64(0)
		if maxVEnd > bias {
			need = alignUp(maxVEnd-bias, segAlign)
		}
		if o := max(base, need); o-base <= MaxLegacyPadding {
			return o, o + bias, true
		}
	}
	return base, alignUp(maxVEnd, segAlign) + base%segAlign, false
}

// layout computes the signed form of the original file f with pkcs7.
func (f *elfFile) layout(pkcs7 []byte) (*elfLayout, error) {
	if len(pkcs7) == 0 {
		return nil, errors.New("authentielf: empty signature")
	}
	if len(pkcs7) > MaxPKCS7Size {
		return nil, fmt.Errorf("authentielf: PKCS#7 blob is %d bytes, maximum is %d", len(pkcs7), MaxPKCS7Size)
	}
	if err := f.checkOriginal(); err != nil {
		return nil, err
	}

	// --- Program headers ---------------------------------------------------
	firstLoad, lastLoad := -1, -1
	var maxAlign, maxVEnd uint64
	for i, p := range f.progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if firstLoad < 0 {
			firstLoad = i
		}
		lastLoad = i
		maxAlign = max(maxAlign, p.Align)
		e := p.Vaddr + p.Memsz
		if e < p.Vaddr {
			return nil, errors.New("authentielf: PT_LOAD wraps address space")
		}
		maxVEnd = max(maxVEnd, e)
	}
	if firstLoad < 0 {
		return nil, errors.New("authentielf: no PT_LOAD segment")
	}
	// The binary's own alignment encodes the largest page size it supports;
	// cap it at 64 KiB to bound padding.
	segAlign := min(max(maxAlign, 0x1000), 0x10000)
	origSize := uint64(len(f.data))
	off, vaddr, legacy := f.placement(segAlign, maxVEnd, f.progs[firstLoad])

	newPhnum := len(f.progs) + 2
	if newPhnum >= pnXnum {
		return nil, errors.New("authentielf: too many program headers")
	}
	phdrSize := uint64(newPhnum * f.phentsize())
	secOff := alignUp(off+phdrSize, sectionAlign)
	secVaddr := vaddr + (secOff - off)
	entryLen := EntryHeaderSize + len(pkcs7)
	secSize := alignUp(uint64(entryLen), sectionAlign)
	loadEnd := secOff + secSize
	loadSize := loadEnd - off
	if vaddr < maxVEnd || vaddr+loadSize < vaddr || (!f.is64 && vaddr+loadSize > math.MaxUint32) {
		return nil, errors.New("authentielf: no room in address space")
	}

	progs := make([]progHeader, 0, newPhnum)
	for i, p := range f.progs {
		if p.Type == elf.PT_PHDR {
			p.Off, p.Vaddr, p.Paddr = off, vaddr, vaddr
			p.Filesz, p.Memsz = phdrSize, phdrSize
		}
		progs = append(progs, p)
		if i == lastLoad { // PT_LOAD entries must stay sorted by vaddr
			progs = append(progs, progHeader{
				Type: elf.PT_LOAD, Flags: elf.PF_R,
				Off: off, Vaddr: vaddr, Paddr: vaddr,
				Filesz: loadSize, Memsz: loadSize, Align: segAlign,
			})
		}
	}
	progs = append(progs, progHeader{
		Type: PT_AUTHENTIELF, Flags: elf.PF_R,
		Off: secOff, Vaddr: secVaddr, Paddr: secVaddr,
		Filesz: secSize, Memsz: secSize, Align: sectionAlign,
	})

	// --- Note: what the header patch overwrites ----------------------------
	ehsize := int(f.hdr.Ehsize)
	desc := make([]byte, 16+ehsize)
	f.bo.PutUint32(desc[0:], noteVersion)
	f.bo.PutUint32(desc[4:], 0) // reserved
	f.bo.PutUint64(desc[8:], origSize)
	copy(desc[16:], f.data[:ehsize])
	note := f.encodeNote(NoteName, NoteTypeOrigin, desc)
	noteOff := loadEnd

	// --- Section headers ---------------------------------------------------
	sects := append([]sectHeader(nil), f.sects...)
	if len(sects) == 0 {
		sects = append(sects, sectHeader{}) // SHN_UNDEF
	}
	shstrndx := f.shstrndx
	var strtab []byte
	if shstrndx != 0 {
		st := f.sects[shstrndx]
		strtab = append([]byte(nil), f.data[st.Off:st.Off+st.Size]...)
		if len(strtab) == 0 || strtab[len(strtab)-1] != 0 {
			strtab = append(strtab, 0)
		}
	} else {
		strtab = []byte{0}
	}
	addName := func(s string) uint32 {
		o := uint32(len(strtab))
		strtab = append(strtab, s+"\x00"...)
		return o
	}
	sects = append(sects,
		sectHeader{Name: addName(SectionName), Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC,
			Addr: secVaddr, Off: secOff, Size: secSize, Addralign: sectionAlign},
		sectHeader{Name: addName(NoteSectionName), Type: elf.SHT_NOTE,
			Off: noteOff, Size: uint64(len(note)), Addralign: 4},
	)
	if shstrndx == 0 {
		shstrndx = len(sects)
		sects = append(sects, sectHeader{Name: addName(".shstrtab"), Type: elf.SHT_STRTAB, Addralign: 1})
	}
	strOff := noteOff + uint64(len(note))
	sects[shstrndx].Off = strOff
	sects[shstrndx].Size = uint64(len(strtab))
	shOff := alignUp(strOff+uint64(len(strtab)), f.ptrAlign())
	shnum := len(sects)
	eShnum, eShstrndx := uint16(0), uint16(shnXindex)
	sects[0].Size, sects[0].Link = 0, 0
	if shnum >= shnLoreserve {
		sects[0].Size = uint64(shnum)
	} else {
		eShnum = uint16(shnum)
	}
	if shstrndx >= shnLoreserve {
		sects[0].Link = uint32(shstrndx)
	} else {
		eShstrndx = uint16(shstrndx)
	}
	end := shOff + uint64(shnum*f.shentsize())
	if !f.is64 && end > math.MaxUint32 {
		return nil, errors.New("authentielf: file too large for ELF32")
	}

	// --- Assemble ----------------------------------------------------------
	hdr := append([]byte(nil), f.data[:ehsize]...)
	f.putHeaderTables(hdr, off, newPhnum, shOff, eShnum, eShstrndx)
	tail := make([]byte, end-origSize)
	at := func(o uint64) []byte { return tail[o-origSize:] }
	for i, p := range progs {
		copy(at(off+uint64(i*f.phentsize())), f.encodeProg(p))
	}
	binary.LittleEndian.PutUint32(at(secOff), uint32(entryLen))
	binary.LittleEndian.PutUint16(at(secOff+4), EntryVersion)
	copy(at(secOff+EntryHeaderSize), pkcs7)
	copy(at(noteOff), note)
	copy(at(strOff), strtab)
	for i, s := range sects {
		copy(at(shOff+uint64(i*f.shentsize())), f.encodeSect(s))
	}
	return &elfLayout{hdr: hdr, tail: tail, info: ContainerInfo{
		OriginalSize: origSize, SectionOffset: secOff, SectionVaddr: secVaddr,
		SectionSize: secSize, Padding: off - alignUp(origSize, sectionAlign), Legacy: legacy,
	}}, nil
}

func (f *elfFile) encodeNote(name string, typ uint32, desc []byte) []byte {
	nb := append([]byte(name), 0)
	out := make([]byte, 12+alignUp(uint64(len(nb)), 4)+alignUp(uint64(len(desc)), 4))
	f.bo.PutUint32(out[0:], uint32(len(nb)))
	f.bo.PutUint32(out[4:], uint32(len(desc)))
	f.bo.PutUint32(out[8:], typ)
	copy(out[12:], nb)
	copy(out[12+alignUp(uint64(len(nb)), 4):], desc)
	return out
}

// openContainer parses a signed file, rebuilds the original and checks that
// the file is exactly layout(original, pkcs7). It returns ErrNotSigned if
// the file has no AuthentiELF structures at all.
func openContainer(data []byte) (*container, error) {
	f, err := parseELF(data)
	if err != nil {
		return nil, fmt.Errorf("authentielf: %w", err)
	}
	sigIdx, noteIdx, nSig, nNote, nPT := 0, 0, 0, 0, 0
	for i := 1; i < len(f.sects); i++ {
		switch f.sectionName(i) {
		case SectionName:
			sigIdx, nSig = i, nSig+1
		case NoteSectionName:
			noteIdx, nNote = i, nNote+1
		}
	}
	for _, p := range f.progs {
		if p.Type == PT_AUTHENTIELF {
			nPT++
		}
	}
	if nSig == 0 && nNote == 0 && nPT == 0 {
		return nil, ErrNotSigned
	}
	if nSig != 1 || nNote != 1 || nPT != 1 {
		return nil, ErrNotCanonical
	}
	ss, ns := f.sects[sigIdx], f.sects[noteIdx]
	if !rangeOK(ss.Off, ss.Size, len(data)) || !rangeOK(ns.Off, ns.Size, len(data)) {
		return nil, ErrNotCanonical
	}

	// Original-file record.
	ehsize := int(f.hdr.Ehsize)
	note := data[ns.Off : ns.Off+ns.Size]
	nameLen := alignUp(uint64(len(NoteName)+1), 4)
	descLen := uint64(16 + ehsize)
	if uint64(len(note)) != 12+nameLen+descLen ||
		f.bo.Uint32(note[0:]) != uint32(len(NoteName)+1) ||
		f.bo.Uint32(note[4:]) != uint32(descLen) ||
		f.bo.Uint32(note[8:]) != NoteTypeOrigin ||
		string(note[12:12+len(NoteName)]) != NoteName {
		return nil, ErrNotCanonical
	}
	desc := note[12+nameLen:]
	if f.bo.Uint32(desc[0:]) != noteVersion {
		return nil, fmt.Errorf("authentielf: unsupported note version %d", f.bo.Uint32(desc[0:]))
	}
	origSize := f.bo.Uint64(desc[8:])
	if origSize < uint64(ehsize) || origSize > uint64(len(data)) {
		return nil, ErrNotCanonical
	}
	original := make([]byte, origSize)
	copy(original, desc[16:16+ehsize])
	copy(original[ehsize:], data[ehsize:origSize])

	// Signature entry.
	sec := data[ss.Off : ss.Off+ss.Size]
	if len(sec) < EntryHeaderSize {
		return nil, ErrNotCanonical
	}
	entryLen := uint64(binary.LittleEndian.Uint32(sec[0:]))
	if v := binary.LittleEndian.Uint16(sec[4:]); v != EntryVersion {
		return nil, fmt.Errorf("authentielf: unsupported entry version %d", v)
	}
	if entryLen <= EntryHeaderSize || entryLen > uint64(len(sec)) {
		return nil, ErrNotCanonical
	}
	pkcs7 := append([]byte(nil), sec[EntryHeaderSize:entryLen]...)

	// Rebuild and compare.
	of, err := parseELF(original)
	if err != nil {
		return nil, fmt.Errorf("%w: original: %v", ErrNotCanonical, err)
	}
	l, err := of.layout(pkcs7)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	if !bytes.Equal(data[:ehsize], l.hdr) || !bytes.Equal(data[origSize:], l.tail) {
		return nil, ErrNotCanonical
	}
	return &container{original: original, pkcs7: pkcs7, info: l.info}, nil
}

// Original returns the unsigned original of data: the file as it was before
// the first signature was added (data itself if it is not signed).
func Original(data []byte) ([]byte, error) {
	c, err := openContainer(data)
	if errors.Is(err, ErrNotSigned) {
		return data, nil
	}
	if err != nil {
		return nil, err
	}
	return c.original, nil
}

// IsSigned reports whether data carries a valid AuthentiELF container.
func IsSigned(data []byte) bool {
	_, err := openContainer(data)
	return err == nil
}

// Inspect describes the AuthentiELF structures of a signed file.
func Inspect(data []byte) (*ContainerInfo, error) {
	c, err := openContainer(data)
	if err != nil {
		return nil, err
	}
	info := c.info
	return &info, nil
}

// Digest computes the AuthentiELF image digest: the hash of the original,
// unsigned file. For an unsigned file this is simply H(file); for a signed
// file the original is rebuilt first, so the digest is the same before and
// after (re-)signing.
func Digest(data []byte, h crypto.Hash) ([]byte, error) {
	orig, err := Original(data)
	if err != nil {
		return nil, err
	}
	return digestOriginal(orig, h)
}

func digestOriginal(orig []byte, h crypto.Hash) ([]byte, error) {
	f, err := parseELF(orig)
	if err != nil {
		return nil, fmt.Errorf("authentielf: %w", err)
	}
	if err := f.checkOriginal(); err != nil {
		return nil, err
	}
	if !h.Available() {
		return nil, fmt.Errorf("authentielf: hash %v not available", h)
	}
	hh := h.New()
	hh.Write(orig)
	return hh.Sum(nil), nil
}

// ReadPKCS7 returns the raw PKCS#7 blob of a signed file.
func ReadPKCS7(data []byte) ([]byte, error) {
	c, err := openContainer(data)
	if err != nil {
		return nil, err
	}
	return c.pkcs7, nil
}

// WritePKCS7 returns the original of data signed with pkcs7 (replacing any
// existing signature blob). An empty pkcs7 returns the unsigned original.
func WritePKCS7(data []byte, pkcs7 []byte) ([]byte, error) {
	orig, err := Original(data)
	if err != nil {
		return nil, err
	}
	if len(pkcs7) == 0 {
		return append([]byte(nil), orig...), nil
	}
	f, err := parseELF(orig)
	if err != nil {
		return nil, fmt.Errorf("authentielf: %w", err)
	}
	l, err := f.layout(pkcs7)
	if err != nil {
		return nil, err
	}
	return l.assemble(orig), nil
}
