package c2embed

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"strings"
)

const (
	peImageCntInitializedData = 0x00000040
	peImageMemExecute         = 0x20000000
)

func isELFMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

func isPEMagic(b []byte) bool {
	return len(b) >= 0x40 && binary.LittleEndian.Uint16(b[0:2]) == 0x5A4D
}

func pickPatchOffsetFromHits(image []byte, hits []int) int {
	if len(hits) == 0 {
		return -1
	}
	for j := len(hits) - 1; j >= 0; j-- {
		off := hits[j]
		p, _ := ParseAt(image, off)
		if isTemplateEmbedBlock(p) {
			return off
		}
	}
	return hits[len(hits)-1]
}

func collectHitsInRange(image []byte, lo, hi int, hits *[]int) {
	if lo < 0 {
		lo = 0
	}
	if hi > len(image) {
		hi = len(image)
	}
	if hi-lo < TotalSize {
		return
	}
	for i := lo; i+TotalSize <= hi; i++ {
		if !bytes.Equal(image[i:i+MagicLen], magicBytes) {
			continue
		}
		if _, err := ParseAt(image, i); err != nil {
			continue
		}
		*hits = append(*hits, i)
	}
}

func peSectionFileRange(s *pe.Section, fileLen int) (lo, hi int) {
	lo = int(s.Offset)
	if lo <= 0 || lo >= fileLen {
		return 0, 0
	}
	n := int(s.Size)
	if n < 0 {
		return 0, 0
	}
	hi = lo + n
	if hi > fileLen {
		hi = fileLen
	}
	return lo, hi
}

// findPatchOffsetPE 仅在 PE 已初始化数据节内搜索，避免误匹配 DOS/间隙等文件偏移（运行时 .rdata 中的 g_c2_embed 与磁盘假命中不一致）。
func findPatchOffsetPE(image []byte) (off int, parsed bool) {
	r := bytes.NewReader(image)
	f, err := pe.NewFile(r)
	if err != nil {
		return -1, false
	}
	defer f.Close()

	var hits []int
	for _, s := range f.Sections {
		name := s.Name
		if !strings.HasPrefix(name, ".rdata") {
			continue
		}
		if s.Size == 0 {
			continue
		}
		lo, hi := peSectionFileRange(s, len(image))
		collectHitsInRange(image, lo, hi, &hits)
	}
	if len(hits) > 0 {
		return pickPatchOffsetFromHits(image, hits), true
	}

	hits = hits[:0]
	for _, s := range f.Sections {
		name := s.Name
		if strings.HasPrefix(name, ".rdata") {
			continue
		}
		if s.Size == 0 || s.Offset == 0 {
			continue
		}
		if s.Characteristics&peImageCntInitializedData == 0 {
			continue
		}
		if s.Characteristics&peImageMemExecute != 0 {
			continue
		}
		lo, hi := peSectionFileRange(s, len(image))
		collectHitsInRange(image, lo, hi, &hits)
	}
	if len(hits) > 0 {
		return pickPatchOffsetFromHits(image, hits), true
	}

	return -1, true
}

// findPatchOffsetELF 仅在 PT_LOAD 可加载段的文件映像内搜索，与进程实际映射一致。
func findPatchOffsetELF(image []byte) (off int, parsed bool) {
	r := bytes.NewReader(image)
	f, err := elf.NewFile(r)
	if err != nil {
		return -1, false
	}
	defer f.Close()

	var hits []int
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || p.Filesz == 0 {
			continue
		}
		lo := int(p.Off)
		hi := lo + int(p.Filesz)
		collectHitsInRange(image, lo, hi, &hits)
	}
	if len(hits) > 0 {
		return pickPatchOffsetFromHits(image, hits), true
	}
	return -1, true
}

func findPatchOffsetRaw(image []byte) int {
	var hits []int
	collectHitsInRange(image, 0, len(image), &hits)
	return pickPatchOffsetFromHits(image, hits)
}
