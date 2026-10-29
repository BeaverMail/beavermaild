package imap

import "github.com/BeaverMail/beavermaild/internal/mail"

func flatSearchCrits(expr mail.SearchExpr) []mail.SearchCriteria {
	return flatSearchCritsPtr(&expr)
}

func flatSearchCritsPtr(expr *mail.SearchExpr) []mail.SearchCriteria {
	if expr == nil {
		return nil
	}
	switch expr.Kind {
	case mail.SearchExprCrit:
		return []mail.SearchCriteria{expr.Crit}
	case mail.SearchExprAnd:
		var out []mail.SearchCriteria
		for _, child := range expr.And {
			out = append(out, flatSearchCritsPtr(child)...)
		}
		return out
	default:
		return nil
	}
}

func findSearchCrit(crits []mail.SearchCriteria, pred func(mail.SearchCriteria) bool) (mail.SearchCriteria, bool) {
	for _, c := range crits {
		if pred(c) {
			return c, true
		}
	}
	return mail.SearchCriteria{}, false
}
