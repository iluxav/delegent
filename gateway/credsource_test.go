package gateway

import (
	"context"
	"testing"
)

func TestStaticSource_ReturnsCred(t *testing.T) {
	s := staticSource{cred: "tok"}
	got, err := s.Bearer(context.Background())
	if err != nil || got != "tok" {
		t.Fatalf("static bearer: %q %v", got, err)
	}
}
