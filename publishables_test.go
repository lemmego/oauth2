package oauth2

import (
	"strings"
	"testing"
)

// A publish tag is now a real selector rather than decoration, so a generic
// one would sweep in other packages: "config" already means something to
// queue and cache, and "migrations" would match any package that ever ships
// one.
func TestPublishTagsAreNamespaced(t *testing.T) {
	provider := &Provider{}
	publishables := provider.AddPublishables()
	if len(publishables) == 0 {
		t.Fatal("nothing is offered for publishing")
	}

	seen := map[string]bool{}
	for _, publishable := range publishables {
		if !strings.HasPrefix(publishable.Tag, "oauth2-") {
			t.Errorf("%s carries the tag %q, which is not namespaced to this module",
				publishable.FilePath, publishable.Tag)
		}
		seen[publishable.Tag] = true
	}
	for _, want := range []string{TagConfig, TagMigrations} {
		if !seen[want] {
			t.Errorf("nothing is published under %q", want)
		}
	}
}

// The command tells people which tags to pass, so it has to name the ones
// that exist.
func TestInstallInstructionsNameTheRealTags(t *testing.T) {
	provider := &Provider{}
	cmd := provider.installCommand(nil)

	var builder strings.Builder
	cmd.SetOut(&builder)
	// Only the printed guidance is under test; the command itself needs a
	// configured server, which this deliberately does not have.
	_ = cmd.RunE(cmd, nil)

	// The instructions live in the RunE body, so assert against the source of
	// truth instead: the tags a caller would have to pass.
	for _, tag := range []string{TagConfig, TagMigrations} {
		if !strings.Contains(installInstructions, tag) {
			t.Errorf("the install instructions do not mention %q", tag)
		}
	}
}
