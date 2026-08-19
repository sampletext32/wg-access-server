//go:build !linux

package amnezia

import "errors"

func New(Options) (Interface, error) {
	return nil, errors.New("AmneziaWG userspace runtime requires Linux")
}
