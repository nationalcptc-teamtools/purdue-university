//go:build darwin

package archive

import "golang.org/x/sys/unix"

func publish(src, dst string) error { return unix.RenamexNp(src, dst, unix.RENAME_EXCL) }
