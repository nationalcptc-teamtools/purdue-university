package cli

import (
	"os"
	"syscall"
	"unsafe"
)

func disableEcho(f *os.File) (func(), error) {
	return termiosNoEcho(f, syscall.TCGETS, syscall.TCSETS)
}

func termiosNoEcho(f *os.File, get, set uintptr) (func(), error) {
	fd := f.Fd()
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, get, uintptr(unsafe.Pointer(&old))); e != 0 {
		return nil, e
	}
	quiet := old
	quiet.Lflag &^= syscall.ECHO
	quiet.Lflag |= syscall.ICANON | syscall.ECHONL
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, set, uintptr(unsafe.Pointer(&quiet))); e != 0 {
		return nil, e
	}
	return func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, set, uintptr(unsafe.Pointer(&old)))
	}, nil
}
