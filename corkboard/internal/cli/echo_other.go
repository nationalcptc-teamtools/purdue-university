//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !windows

package cli

import (
	"errors"
	"os"
)

func disableEcho(*os.File) (func(), error) {
	return nil, errors.New("hiding input is not supported on this platform")
}
