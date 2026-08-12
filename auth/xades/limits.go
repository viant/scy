package xades

import (
	"errors"
	"fmt"

	"github.com/beevik/etree"
)

const (
	DefaultMaxDocumentBytes = 32 << 20
	DefaultMaxXMLDepth      = 256
)

func parseXML(data []byte, maxBytes, maxDepth int, label string) (*etree.Document, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxDocumentBytes
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxXMLDepth
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("%s exceeds maximum size of %d bytes", label, maxBytes)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", label, err)
	}
	if doc.Root() == nil {
		return nil, errors.New(label + " has no root element")
	}
	type depthEntry struct {
		element *etree.Element
		depth   int
	}
	stack := []depthEntry{{element: doc.Root(), depth: 1}}
	for len(stack) > 0 {
		last := len(stack) - 1
		entry := stack[last]
		stack = stack[:last]
		if entry.depth > maxDepth {
			return nil, fmt.Errorf("%s exceeds maximum XML depth of %d", label, maxDepth)
		}
		for _, child := range entry.element.ChildElements() {
			stack = append(stack, depthEntry{element: child, depth: entry.depth + 1})
		}
	}
	return doc, nil
}
