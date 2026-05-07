package http

import "net/http"

const (
	clientNameHeader    = "Bitwarden-Client-Name"
	clientVersionHeader = "Bitwarden-Client-Version"
	clientName          = "desktop"
	clientVersion       = "0.1.0"
)

func setBitwardenClientHeaders(req *http.Request) {
	req.Header.Set(clientNameHeader, clientName)
	req.Header.Set(clientVersionHeader, clientVersion)
}
