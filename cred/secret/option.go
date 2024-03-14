package secret

import (
	"embed"
)

// Option represents a service option
type Option func(s *Service)

// WithBaseDirectory sets base directory
func WithBaseDirectory(baseDirectory string) Option {
	return func(s *Service) {
		s.baseDirectory = baseDirectory
	}
}

// WithFileSystem sets file system
func WithFileSystem(fs *embed.FS) Option {
	return func(s *Service) {
		s.embedFS = fs
	}
}
