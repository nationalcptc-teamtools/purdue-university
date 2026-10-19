//go:build !linux && !darwin && !windows

package archive

import (
	"fmt"
	"os"
)

func publish(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("destination already exists: %s", dst)
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(src, dst)
}
