//go:build !stubembed

package payload

import "os"

func tryLoadEmbeddedStub(osKey string) ([]byte, error) {
	_ = osKey
	return nil, os.ErrNotExist
}
