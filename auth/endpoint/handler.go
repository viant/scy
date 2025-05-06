package endpoint

import (
	_ "embed"
	"net/url"

	"net/http"
)

//go:embed asset/success.html
var content string

type httpHandler struct {
	values url.Values
	done   chan bool
}

func (h *httpHandler) handle(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err == nil {
		h.values = request.Form
	}
	writer.Header().Set("Content-Type", "text/html")
	_, _ = writer.Write([]byte(content))
	h.done <- true
}

// ServeHTTP handler endpoint requests
func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.handle(writer, request)
}

// AuthCode returns auth codde
func (h *httpHandler) AuthCode() string {
	if len(h.values) > 0 {
		return h.values.Get("code")
	}
	return ""
}

func newHttpHandler() *httpHandler {
	return &httpHandler{
		done: make(chan bool, 2),
	}
}
