module delegent.dev/gateway

go 1.25.0

require (
	delegent.dev/protocol v0.0.0
	github.com/modelcontextprotocol/go-sdk v1.6.1
)

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

// The protocol library lives in ../protocol in the same repo. The gateway module is
// versioned and released with it; the replace keeps builds hermetic without a go.work.
replace delegent.dev/protocol => ../protocol
