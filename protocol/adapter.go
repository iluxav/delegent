package protocol

// Adapter data shapes, loaded from adapters/<vendor>/adapter.json. These are DATA,
// not policy code — the classification lives in the JSON, interpreted identically by
// classify(). Note: in the JSON, `method` is the method NAME string ("POST"), not the
// bitmask; classify converts it to a bit for the Classified result.

type MatchSpec struct {
	Action *string        `json:"action,omitempty"`
	Method *string        `json:"method,omitempty"`
	Path   *string        `json:"path,omitempty"`
	Body   map[string]any `json:"body,omitempty"`
}

type ClassifyRule struct {
	ID     string     `json:"id,omitempty"`
	Match  *MatchSpec `json:"match,omitempty"` // nil => a section-comment entry, matches nothing
	Effect string     `json:"effect"`
	Method *string    `json:"method,omitempty"` // demo-style rules carry the method here
	Scopes []string   `json:"scopes"`
	Meters []string   `json:"meters,omitempty"`
}

type Adapter struct {
	Vendor   string         `json:"vendor"`
	Version  string         `json:"version"`
	Classify []ClassifyRule `json:"classify"`
	Default  struct {
		Effect string `json:"effect"`
	} `json:"default"`
}
