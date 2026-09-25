package brains

import "testing"

func TestWantsEmail(t *testing.T) {
	cases := []struct {
		in   string
		to   string
		want bool
	}{
		{"research solar and email the summary to bob@acme.example", "bob@acme.example", true},
		{"research solar and write a short summary. Do not email it; just return the summary.", "", false},
		{"research solar, don't send it to anyone", "", false},
		{"research solar and email the summary", "", false}, // no address: never guess one
		{"research solar", "", false},
	}
	for _, c := range cases {
		to, ok := wantsEmail(c.in)
		if ok != c.want || to != c.to {
			t.Errorf("wantsEmail(%q) = %q,%v want %q,%v", c.in, to, ok, c.to, c.want)
		}
	}
}

func TestTopic(t *testing.T) {
	for in, want := range map[string]string{
		"research solar panels and email the summary to bob@acme.example": "solar panels",
		"Research the history of espresso. Be brief.":                     "the history of espresso",
		"coffee": "coffee",
	} {
		if got := topic(in); got != want {
			t.Errorf("topic(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTopicOfBareSendRequestIsEmpty(t *testing.T) {
	for _, in := range []string{"email it to bob@acme.example", "send the report to bob@acme.example", "Email it to foo@bar.com."} {
		if got := topic(in); got != "" {
			t.Errorf("topic(%q) = %q, want empty (nothing to research)", in, got)
		}
	}
}

func TestCovers(t *testing.T) {
	desc := "Finds notes. Topics covered: solar panels, Delegent, coffee. Nothing else is indexed."
	if !covers(desc, "research solar panel efficiency") || !covers(desc, "what is delegent") || !covers(desc, "Coffee brewing") {
		t.Error("covered topics not recognised")
	}
	if covers(desc, "research how the Rust language is used on Linux") {
		t.Error("an uncovered topic must not engage the archive")
	}
	if !covers("Finds notes on anything.", "rust") {
		t.Error("a description without a coverage line means everything")
	}
}
