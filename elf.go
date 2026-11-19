package authentielf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

// Low-level ELF reader/writer.
//
// debug/elf is not used because AuthentiELF needs exact file offsets of every
// header and must be able to re-emit headers bit-for-bit; debug/elf hides
// those details. Everything read here is treated as untrusted input: every
// offset/size is bounds-checked before use.

const (
	shnLoreserve = 0xff00
	shnXindex    = 0xffff
	pnXnum       = 0xffff
)

type elfHeader struct {
	Type      elf.Type
	Phoff     uint64
	Shoff     uint64
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type progHeader struct {
	Type   elf.ProgType
	Flags  elf.ProgFlag
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

type sectHeader struct {
	Name      uint32
	Type      elf.SectionType
	Flags     elf.SectionFlag
	Addr      uint64
	Off       uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

type elfFile struct {
	data  []byte
	is64  bool
	bo    binary.ByteOrder
	hdr   elfHeader
	progs []progHeader
	sects []sectHeader
	// Resolved (extended-numbering aware) values.
	shnum    int
	shstrndx int // 0 when there is no section name table
}

func (f *elfFile) phentsize() int {
	if f.is64 {
		return 56
	}
	return 32
}

func (f *elfFile) shentsize() int {
	if f.is64 {
		return 64
	}
	return 40
}

func (f *elfFile) ptrAlign() uint64 {
	if f.is64 {
		return 8
	}
	return 4
}

// rangeOK reports whether [off, off+size) lies inside a buffer of length n.
func rangeOK(off, size uint64, n int) bool {
	end := off + size
	return end >= off && end <= uint64(n)
}

func parseELF(data []byte) (*elfFile, error) {
	if len(data) < 16 || !bytes.Equal(data[:4], []byte(elf.ELFMAG)) {
		return nil, errors.New("not an ELF file")
	}
	f := &elfFile{data: data}
	switch elf.Class(data[elf.EI_CLASS]) {
	case elf.ELFCLASS32:
	case elf.ELFCLASS64:
		f.is64 = true
	default:
		return nil, fmt.Errorf("unsupported ELF class %d", data[elf.EI_CLASS])
	}
	switch elf.Data(data[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		f.bo = binary.LittleEndian
	case elf.ELFDATA2MSB:
		f.bo = binary.BigEndian
	default:
		return nil, fmt.Errorf("unsupported ELF data encoding %d", data[elf.EI_DATA])
	}
	ehsize := 52
	if f.is64 {
		ehsize = 64
	}
	if len(data) < ehsize {
		return nil, errors.New("truncated ELF header")
	}
	bo := f.bo
	h := &f.hdr
	h.Type = elf.Type(bo.Uint16(data[16:]))
	if f.is64 {
		h.Phoff = bo.Uint64(data[32:])
		h.Shoff = bo.Uint64(data[40:])
		h.Ehsize = bo.Uint16(data[52:])
		h.Phentsize = bo.Uint16(data[54:])
		h.Phnum = bo.Uint16(data[56:])
		h.Shentsize = bo.Uint16(data[58:])
		h.Shnum = bo.Uint16(data[60:])
		h.Shstrndx = bo.Uint16(data[62:])
	} else {
		h.Phoff = uint64(bo.Uint32(data[28:]))
		h.Shoff = uint64(bo.Uint32(data[32:]))
		h.Ehsize = bo.Uint16(data[40:])
		h.Phentsize = bo.Uint16(data[42:])
		h.Phnum = bo.Uint16(data[44:])
		h.Shentsize = bo.Uint16(data[46:])
		h.Shnum = bo.Uint16(data[48:])
		h.Shstrndx = bo.Uint16(data[50:])
	}
	if int(h.Ehsize) != ehsize {
		return nil, fmt.Errorf("unexpected e_ehsize %d", h.Ehsize)
	}

	// Section headers (read first: extended numbering lives in section 0).
	if h.Shoff != 0 {
		if int(h.Shentsize) != f.shentsize() {
			return nil, fmt.Errorf("unexpected e_shentsize %d", h.Shentsize)
		}
		shnum := uint64(h.Shnum)
		if !rangeOK(h.Shoff, uint64(f.shentsize()), len(data)) {
			return nil, errors.New("section header table out of range")
		}
		s0 := f.decodeSect(data[h.Shoff:])
		if shnum == 0 {
			shnum = s0.Size
		}
		if shnum > uint64(len(data))/uint64(f.shentsize()) ||
			!rangeOK(h.Shoff, shnum*uint64(f.shentsize()), len(data)) {
			return nil, errors.New("section header table out of range")
		}
		f.shnum = int(shnum)
		f.sects = make([]sectHeader, f.shnum)
		for i := range f.sects {
			f.sects[i] = f.decodeSect(data[h.Shoff+uint64(i*f.shentsize()):])
		}
		f.shstrndx = int(h.Shstrndx)
		if h.Shstrndx == shnXindex && f.shnum > 0 {
			f.shstrndx = int(f.sects[0].Link)
		}
		if f.shstrndx >= f.shnum {
			return nil, errors.New("e_shstrndx out of range")
		}
		if f.shstrndx != 0 {
			s := f.sects[f.shstrndx]
			if s.Type != elf.SHT_STRTAB || !rangeOK(s.Off, s.Size, len(data)) {
				return nil, errors.New("invalid section name string table")
			}
		}
	}

	// Program headers.
	phnum := int(h.Phnum)
	if h.Phnum == pnXnum {
		if f.shnum == 0 {
			return nil, errors.New("PN_XNUM without section header table")
		}
		phnum = int(f.sects[0].Info)
	}
	if phnum > 0 {
		if int(h.Phentsize) != f.phentsize() {
			return nil, fmt.Errorf("unexpected e_phentsize %d", h.Phentsize)
		}
		if !rangeOK(h.Phoff, uint64(phnum)*uint64(f.phentsize()), len(data)) {
			return nil, errors.New("program header table out of range")
		}
		f.progs = make([]progHeader, phnum)
		for i := range f.progs {
			f.progs[i] = f.decodeProg(data[h.Phoff+uint64(i*f.phentsize()):])
		}
	}
	return f, nil
}

func (f *elfFile) decodeProg(b []byte) progHeader {
	bo := f.bo
	if f.is64 {
		return progHeader{
			Type:   elf.ProgType(bo.Uint32(b[0:])),
			Flags:  elf.ProgFlag(bo.Uint32(b[4:])),
			Off:    bo.Uint64(b[8:]),
			Vaddr:  bo.Uint64(b[16:]),
			Paddr:  bo.Uint64(b[24:]),
			Filesz: bo.Uint64(b[32:]),
			Memsz:  bo.Uint64(b[40:]),
			Align:  bo.Uint64(b[48:]),
		}
	}
	return progHeader{
		Type:   elf.ProgType(bo.Uint32(b[0:])),
		Off:    uint64(bo.Uint32(b[4:])),
		Vaddr:  uint64(bo.Uint32(b[8:])),
		Paddr:  uint64(bo.Uint32(b[12:])),
		Filesz: uint64(bo.Uint32(b[16:])),
		Memsz:  uint64(bo.Uint32(b[20:])),
		Flags:  elf.ProgFlag(bo.Uint32(b[24:])),
		Align:  uint64(bo.Uint32(b[28:])),
	}
}

func (f *elfFile) encodeProg(p progHeader) []byte {
	bo := f.bo
	b := make([]byte, f.phentsize())
	if f.is64 {
		bo.PutUint32(b[0:], uint32(p.Type))
		bo.PutUint32(b[4:], uint32(p.Flags))
		bo.PutUint64(b[8:], p.Off)
		bo.PutUint64(b[16:], p.Vaddr)
		bo.PutUint64(b[24:], p.Paddr)
		bo.PutUint64(b[32:], p.Filesz)
		bo.PutUint64(b[40:], p.Memsz)
		bo.PutUint64(b[48:], p.Align)
	} else {
		bo.PutUint32(b[0:], uint32(p.Type))
		bo.PutUint32(b[4:], uint32(p.Off))
		bo.PutUint32(b[8:], uint32(p.Vaddr))
		bo.PutUint32(b[12:], uint32(p.Paddr))
		bo.PutUint32(b[16:], uint32(p.Filesz))
		bo.PutUint32(b[20:], uint32(p.Memsz))
		bo.PutUint32(b[24:], uint32(p.Flags))
		bo.PutUint32(b[28:], uint32(p.Align))
	}
	return b
}

func (f *elfFile) decodeSect(b []byte) sectHeader {
	bo := f.bo
	if f.is64 {
		return sectHeader{
			Name:      bo.Uint32(b[0:]),
			Type:      elf.SectionType(bo.Uint32(b[4:])),
			Flags:     elf.SectionFlag(bo.Uint64(b[8:])),
			Addr:      bo.Uint64(b[16:]),
			Off:       bo.Uint64(b[24:]),
			Size:      bo.Uint64(b[32:]),
			Link:      bo.Uint32(b[40:]),
			Info:      bo.Uint32(b[44:]),
			Addralign: bo.Uint64(b[48:]),
			Entsize:   bo.Uint64(b[56:]),
		}
	}
	return sectHeader{
		Name:      bo.Uint32(b[0:]),
		Type:      elf.SectionType(bo.Uint32(b[4:])),
		Flags:     elf.SectionFlag(bo.Uint32(b[8:])),
		Addr:      uint64(bo.Uint32(b[12:])),
		Off:       uint64(bo.Uint32(b[16:])),
		Size:      uint64(bo.Uint32(b[20:])),
		Link:      bo.Uint32(b[24:]),
		Info:      bo.Uint32(b[28:]),
		Addralign: uint64(bo.Uint32(b[32:])),
		Entsize:   uint64(bo.Uint32(b[36:])),
	}
}

func (f *elfFile) encodeSect(s sectHeader) []byte {
	bo := f.bo
	b := make([]byte, f.shentsize())
	if f.is64 {
		bo.PutUint32(b[0:], s.Name)
		bo.PutUint32(b[4:], uint32(s.Type))
		bo.PutUint64(b[8:], uint64(s.Flags))
		bo.PutUint64(b[16:], s.Addr)
		bo.PutUint64(b[24:], s.Off)
		bo.PutUint64(b[32:], s.Size)
		bo.PutUint32(b[40:], s.Link)
		bo.PutUint32(b[44:], s.Info)
		bo.PutUint64(b[48:], s.Addralign)
		bo.PutUint64(b[56:], s.Entsize)
	} else {
		bo.PutUint32(b[0:], s.Name)
		bo.PutUint32(b[4:], uint32(s.Type))
		bo.PutUint32(b[8:], uint32(s.Flags))
		bo.PutUint32(b[12:], uint32(s.Addr))
		bo.PutUint32(b[16:], uint32(s.Off))
		bo.PutUint32(b[20:], uint32(s.Size))
		bo.PutUint32(b[24:], s.Link)
		bo.PutUint32(b[28:], s.Info)
		bo.PutUint32(b[32:], uint32(s.Addralign))
		bo.PutUint32(b[36:], uint32(s.Entsize))
	}
	return b
}

// putHeaderTables patches e_phoff/e_phnum/e_shoff/e_shnum/e_shstrndx in an
// ELF header buffer (all other header bytes are kept as they are).
func (f *elfFile) putHeaderTables(b []byte, phoff uint64, phnum int, shoff uint64, shnum, shstrndx uint16) {
	bo := f.bo
	if f.is64 {
		bo.PutUint64(b[32:], phoff)
		bo.PutUint64(b[40:], shoff)
		bo.PutUint16(b[56:], uint16(phnum))
		bo.PutUint16(b[60:], shnum)
		bo.PutUint16(b[62:], shstrndx)
	} else {
		bo.PutUint32(b[28:], uint32(phoff))
		bo.PutUint32(b[32:], uint32(shoff))
		bo.PutUint16(b[44:], uint16(phnum))
		bo.PutUint16(b[48:], shnum)
		bo.PutUint16(b[50:], shstrndx)
	}
}

// sectionName returns the name of section i, or "" if it cannot be resolved.
func (f *elfFile) sectionName(i int) string {
	if f.shstrndx == 0 {
		return ""
	}
	st := f.sects[f.shstrndx]
	tab := f.data[st.Off : st.Off+st.Size]
	off := uint64(f.sects[i].Name)
	if off >= uint64(len(tab)) {
		return ""
	}
	end := bytes.IndexByte(tab[off:], 0)
	if end < 0 {
		return ""
	}
	return string(tab[off : off+uint64(end)])
}

func alignUp(v, a uint64) uint64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) / a * a
}
