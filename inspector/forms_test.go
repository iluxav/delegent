package main

import (
	"net/url"
	"reflect"
	"testing"
)

func TestSchemaFieldsAndArgs(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":  map[string]any{"type": "string", "description": "who"},
			"count": map[string]any{"type": "integer"},
			"loud":  map[string]any{"type": "boolean"},
			"mode":  map[string]any{"type": "string", "enum": []any{"a", "b"}},
			"opts":  map[string]any{"type": "object"},
			"tags":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
		"required": []any{"name", "count"},
	}
	fields, ok := SchemaFields(schema)
	if !ok {
		t.Fatal("expected fields")
	}
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	// required first, then alphabetical
	if want := []string{"count", "name", "loud", "mode", "opts", "tags"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("order %v, want %v", names, want)
	}

	form := url.Values{"f.name": {"bob"}, "f.count": {"3"}, "f.loud": {"on"}, "f.mode": {"b"}, "f.opts": {`{"k": 1}`}, "f.tags": {""}}
	args, err := ArgsFromForm(fields, form)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "bob", "count": 3.0, "loud": true, "mode": "b", "opts": map[string]any{"k": 1.0}}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args %#v, want %#v", args, want)
	}

	// raw JSON wins over the fields; bad numbers and bad JSON are reported
	args, err = ArgsFromForm(fields, url.Values{"args_json": {`{"x": 1}`}, "f.name": {"ignored"}})
	if err != nil || !reflect.DeepEqual(args, map[string]any{"x": 1.0}) {
		t.Fatalf("raw override: %v %v", args, err)
	}
	if _, err := ArgsFromForm(fields, url.Values{"f.count": {"three"}}); err == nil {
		t.Error("expected a number error")
	}
	if _, err := ArgsFromForm(fields, url.Values{"f.opts": {"{"}}); err == nil {
		t.Error("expected a JSON error")
	}

	// schemas without properties fall back to the raw JSON box
	if _, ok := SchemaFields(map[string]any{"type": "object"}); ok {
		t.Error("expected no fields")
	}
}
