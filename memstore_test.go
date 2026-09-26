package oauth2_test

import (
	"testing"

	"github.com/lemmego/oauth2"
	"github.com/lemmego/oauth2/storetest"
)

func TestMemoryStoreSatisfiesTheContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) oauth2.Store {
		return oauth2.NewMemoryStore()
	})
}
