package dictionary

import (
	"net/url"
	"testing"
)

// This is really just a conventient way of testing that all
// advertised functions exist, but we also verify that all
// URLS are valid and have descriptions.
func TestDictionary(t *testing.T) {
	for i := range Dictionary {
		u, err := url.Parse(i)
		if err != nil {
			t.Error(err)
		}
		if i != u.String() {
			t.Error("Bad URL:", i)
		}
		if Dictionary[i].Description == "" {
			t.Error("No description for", i)
		}
	}
}
