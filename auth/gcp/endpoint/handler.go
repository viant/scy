package endpoint

import (
	"net/http"
	"net/url"
)

var content = `<!DOCTYPE html>
<html>
   <head>
      	<title>HTML Meta Tag</title>
		<meta http-equiv="refresh" content="0; url="https://github.com/viant/scy" />
     </head>
   <body>
      <p>Scy OAuth Client</p>
   </body>
</html>`

type httpHandler struct {
	values url.Values
	done   chan bool
}

func (h *httpHandler) handle(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err == nil {
		h.values = request.Form
	}
	writer.Header().Set("Content-Type", "text/html")
	writer.Write([]byte(content))
	h.done <- true
}

//ServeHTTP handler endpoint requests
func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.handle(writer, request)
}

//AuthCode returns auth codde
func (h *httpHandler) AuthCode() string {
	/*
		https://localhost:8085/?state=Q9X8NrfPqYiqLGFxhudGbIuFnqahSu&code=4/0AX4XfWgKkjKQQRKzVwW8bA6__SapAdcQd0b9XrbAB-YGqAVUmINU-XkVxc3GR1riMaDpGg&scope=email%20openid%20https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/cloud-platform%20https://www.googleapis.com/auth/appengine.admin%20https://www.googleapis.com/auth/compute%20https://www.googleapis.com/auth/accounts.reauth&authuser=0&hd=vindicotech.com&prompt=consent
	*/
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
