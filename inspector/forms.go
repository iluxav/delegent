package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Field is one top-level property of a JSON schema, rendered as a form input. Objects and
// arrays become a JSON textarea; everything else gets a typed input.
type Field struct {
	Name        string
	Type        string // string · number · integer · boolean · object · array
	Title       string
	Description string
	Required    bool
	Enum        []string
	Default     string
	JSON        bool
}

// SchemaFields flattens an object schema's top-level properties into form fields. ok is
// false when the schema is not an object with properties (the raw JSON box is then the
// only way in). The schema is normalized through JSON so both wire maps and SDK structs work.
func SchemaFields(schema any) (fields []Field, ok bool) {
	m := toMap(schema)
	if m == nil {
		return nil, false
	}
	props, _ := m["properties"].(map[string]any)
	if props == nil {
		return nil, false
	}
	required := map[string]bool{}
	if req, _ := m["required"].([]any); req != nil {
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}
	for name, raw := range props {
		p, _ := raw.(map[string]any)
		if p == nil {
			p = map[string]any{}
		}
		f := Field{Name: name, Type: schemaType(p), Required: required[name]}
		f.Title, _ = p["title"].(string)
		f.Description, _ = p["description"].(string)
		if enum, _ := p["enum"].([]any); enum != nil {
			for _, e := range enum {
				f.Enum = append(f.Enum, fmt.Sprint(e))
			}
		}
		if d, has := p["default"]; has {
			if s, isStr := d.(string); isStr {
				f.Default = s
			} else if b, err := json.Marshal(d); err == nil {
				f.Default = string(b)
			}
		}
		f.JSON = f.Type == "object" || f.Type == "array" || f.Type == ""
		fields = append(fields, f)
	}
	// required first, then alphabetical — the order a person fills the form in
	sort.SliceStable(fields, func(i, j int) bool {
		if fields[i].Required != fields[j].Required {
			return fields[i].Required
		}
		return fields[i].Name < fields[j].Name
	})
	return fields, true
}

// ArgsFromForm builds the arguments object. A non-empty "args_json" box wins outright;
// otherwise each field is converted by its schema type, and empty optional fields are left
// out so the server sees exactly what was filled in.
func ArgsFromForm(fields []Field, form url.Values) (map[string]any, error) {
	if raw := strings.TrimSpace(form.Get("args_json")); raw != "" {
		var args map[string]any
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			return nil, fmt.Errorf("arguments JSON: %w", err)
		}
		return args, nil
	}
	args := map[string]any{}
	for _, f := range fields {
		key := "f." + f.Name
		val := strings.TrimSpace(form.Get(key))
		switch {
		case f.Type == "boolean":
			if form.Has(key) {
				args[f.Name] = val == "on" || val == "true"
			} else if f.Required {
				args[f.Name] = false
			}
		case val == "":
			if f.Required && !f.JSON {
				args[f.Name] = ""
			}
		case f.Type == "number" || f.Type == "integer":
			n, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("%s: not a number", f.Name)
			}
			if f.Type == "integer" && n != float64(int64(n)) {
				return nil, fmt.Errorf("%s: not an integer", f.Name)
			}
			args[f.Name] = n
		case f.JSON:
			var v any
			if err := json.Unmarshal([]byte(val), &v); err != nil {
				return nil, fmt.Errorf("%s: not valid JSON (%v)", f.Name, err)
			}
			args[f.Name] = v
		default:
			args[f.Name] = val
		}
	}
	return args, nil
}

// Skeleton is an example arguments object for the raw JSON box's placeholder.
func Skeleton(fields []Field) string {
	ex := map[string]any{}
	for _, f := range fields {
		switch f.Type {
		case "number", "integer":
			ex[f.Name] = 0
		case "boolean":
			ex[f.Name] = false
		case "array":
			ex[f.Name] = []any{}
		case "object":
			ex[f.Name] = map[string]any{}
		default:
			ex[f.Name] = ""
		}
	}
	b, _ := json.MarshalIndent(ex, "", "  ")
	return string(b)
}

func toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// schemaType picks the property's type; for ["string","null"] unions the first non-null.
func schemaType(p map[string]any) string {
	switch t := p["type"].(type) {
	case string:
		return t
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "null" {
				return s
			}
		}
	}
	if _, has := p["properties"]; has {
		return "object"
	}
	if _, has := p["items"]; has {
		return "array"
	}
	if _, has := p["enum"]; has {
		return "string"
	}
	return ""
}
