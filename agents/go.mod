module delegent.dev/agents

go 1.25.0

// Dev-only module: it builds against the sibling gateway (and, through it, protocol) in this
// checkout. Nothing here is published.
replace (
	delegent.dev/gateway => ../gateway
	delegent.dev/protocol => ../protocol
)

require (
	delegent.dev/gateway v0.0.0
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
