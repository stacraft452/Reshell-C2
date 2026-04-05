// PE 子系统修补：文件名不得使用 *_windows.go，否则 GOOS=linux 交叉编译时本文件被排除，
// generator 中 patchPESubsystemWindowsGUI 会未定义。

package payload

import (
	"encoding/binary"
	"fmt"
)

// Windows PE 子系统（winnt.h）
const (
	imageSubsystemWindowsGUI = 2
	imageSubsystemWindowsCUI = 3
	peOptional32Magic        = 0x10b
	peOptional64Magic        = 0x20b
)

// patchPESubsystemWindowsGUI 将控制台子系统(CUI)改为图形界面子系统(GUI)，运行 exe 时不分配控制台窗口。
// 已为 GUI 的 PE 直接返回 nil；非标准子系统则返回错误，避免误改驱动等二进制。
func patchPESubsystemWindowsGUI(b []byte) error {
	if len(b) < 0x40 {
		return fmt.Errorf("文件过小")
	}
	if b[0] != 'M' || b[1] != 'Z' {
		return fmt.Errorf("非 MZ/PE 可执行文件")
	}
	eLfanew := int(binary.LittleEndian.Uint32(b[0x3C:0x40]))
	if eLfanew < 0 || eLfanew+24 > len(b) {
		return fmt.Errorf("无效 e_lfanew")
	}
	if string(b[eLfanew:eLfanew+4]) != "PE\x00\x00" {
		return fmt.Errorf("非 PE 签名")
	}
	optOff := eLfanew + 4 + 20
	if optOff+2 > len(b) {
		return fmt.Errorf("Optional Header 越界")
	}
	magic := binary.LittleEndian.Uint16(b[optOff : optOff+2])
	var subOff int
	switch magic {
	case peOptional32Magic:
		subOff = optOff + 0x40
	case peOptional64Magic:
		subOff = optOff + 0x44
	default:
		return fmt.Errorf("未知 Optional Magic 0x%x", magic)
	}
	if subOff < 0 || subOff+2 > len(b) {
		return fmt.Errorf("Subsystem 偏移越界")
	}
	cur := binary.LittleEndian.Uint16(b[subOff : subOff+2])
	if cur == imageSubsystemWindowsGUI {
		return nil
	}
	if cur != imageSubsystemWindowsCUI {
		return fmt.Errorf("PE Subsystem=%d，仅支持从控制台(CUI=3)改为隐藏控制台(GUI)", cur)
	}
	binary.LittleEndian.PutUint16(b[subOff:subOff+2], imageSubsystemWindowsGUI)
	return nil
}
