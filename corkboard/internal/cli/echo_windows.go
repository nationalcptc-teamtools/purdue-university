package cli

import (
	"os"
	"syscall"
)

const enableEchoInput = 0x0004

var setConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

func disableEcho(f *os.File) (func(), error) {
	h := syscall.Handle(f.Fd())
	var old uint32
	if err := syscall.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	if r, _, err := setConsoleMode.Call(uintptr(h), uintptr(old&^enableEchoInput)); r == 0 {
		return nil, err
	}
	return func() { _, _, _ = setConsoleMode.Call(uintptr(h), uintptr(old)) }, nil
}
