//go:build !windows

package capture

import "os"

func osPageSize() int {
	return os.Getpagesize()
}
