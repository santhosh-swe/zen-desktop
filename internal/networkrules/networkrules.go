package networkrules

import (
	"net/http"
	"net/url"

	"github.com/irbis-sh/zen-desktop/internal/networkrules/exceptionrule"
	"github.com/irbis-sh/zen-desktop/internal/networkrules/rule"
)

type NetworkRules struct {
	primaryStore   *ruleStore[*rule.Rule]
	exceptionStore *ruleStore[*exceptionrule.ExceptionRule]
}

func New() *NetworkRules {
	return &NetworkRules{
		primaryStore:   newRuleStore[*rule.Rule](),
		exceptionStore: newRuleStore[*exceptionrule.ExceptionRule](),
	}
}

// ModifyReq matches the request against the loaded rules and reports whether
// it should be blocked.
//
// Hardened build: network rules are block-only. Rules carrying action or query
// modifiers (removeparam, removeheader, header injection, jsonprune, etc.) are
// matched but never applied, so remotely downloaded filter lists cannot
// rewrite requests, strip parameters, or trigger redirects.
func (nr *NetworkRules) ModifyReq(req *http.Request) (appliedRules []rule.Rule, shouldBlock bool, redirectURL string) {
	reqURL := renderURLWithoutPort(req.URL)

	primaryRules := nr.primaryStore.Get(reqURL)
	primaryRules = filter(primaryRules, func(r *rule.Rule) bool {
		return r.ShouldMatchReq(req)
	})
	if len(primaryRules) == 0 {
		return nil, false, ""
	}

	exceptions := nr.exceptionStore.Get(reqURL)
	exceptions = filter(exceptions, func(er *exceptionrule.ExceptionRule) bool {
		return er.ShouldMatchReq(req)
	})

outer:
	for _, r := range primaryRules {
		for _, ex := range exceptions {
			if ex.Cancels(r) {
				continue outer
			}
		}
		if r.ShouldBlockReq(req) {
			return []rule.Rule{*r}, true, ""
		}
	}

	return nil, false, ""
}

// ModifyRes is a no-op in this hardened build: response modification (header
// removal/injection, body rewriting) would let remotely downloaded filter
// lists alter page security properties, so only request blocking is supported.
func (nr *NetworkRules) ModifyRes(*http.Request, *http.Response) ([]rule.Rule, error) {
	return nil, nil
}

func (nr *NetworkRules) Compact() {
	nr.primaryStore.Compact()
	nr.exceptionStore.Compact()
}

// filter returns a new slice containing only the elements of arr
// that satisfy the predicate.
func filter[T any](arr []T, predicate func(T) bool) []T {
	var res []T
	for _, el := range arr {
		if predicate(el) {
			res = append(res, el)
		}
	}
	return res
}

func renderURLWithoutPort(u *url.URL) string {
	stripped := url.URL{
		Scheme:   u.Scheme,
		Host:     u.Hostname(),
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	return stripped.String()
}
