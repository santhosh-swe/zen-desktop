package app

import (
	"log"
	"strings"
	"sync"

	"github.com/irbis-sh/zen-desktop/internal/filter"
)

const myRulesFilterName = "My rules"

func (a *App) initFilter(filter *filter.Filter) {
	var wg sync.WaitGroup
	for _, filterList := range a.config.GetFilterLists() {
		if !filterList.Enabled {
			continue
		}
		wg.Go(func() {
			// Hardened build: remotely downloaded lists are never treated as
			// trusted, regardless of what the (importable) config says.
			// Trusted-only rule types grant page-injection privileges.
			if err := filter.AddURL(filterList.URL, filterList.Name, false); err != nil {
				log.Printf("failed to add filter list %q to filter: %v", filterList.URL, err)
			}
		})
	}

	wg.Go(func() {
		myRules := a.config.GetRules()
		reader := strings.NewReader(strings.Join(myRules, "\n"))
		if err := filter.AddReader(reader, myRulesFilterName, false); err != nil {
			log.Printf("failed to add my rules to filter: %v", err)
			return
		}
	})

	wg.Wait()

	filter.Finalize()
}
