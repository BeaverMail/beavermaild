// Subject heuristics (reference analysis/subject.rs subset).
package main

import (
	"strings"
	"unicode"
)

func analyzeSubjectRegex(ctx *classifyCtx, res *classifyResult) {
	if ctx.content == nil || ctx.req.BodyPath == "" {
		return
	}
	ok, err := ctx.content.matchSubject(ctx.req.BodyPath)
	if err == nil && ok {
		res.addTag("SUBJECT_BAD")
	}
}

func analyzeSubject(ctx *classifyCtx, res *classifyResult) {
	subject := ctx.msg.Subject
	if subject == "" && ctx.req.BodyPath != "" {
		res.addTag("MISSING_SUBJECT")
		return
	}
	if strings.TrimSpace(subject) == "" {
		res.addTag("EMPTY_SUBJECT")
		return
	}
	if strings.HasSuffix(subject, " ") || strings.HasSuffix(subject, "\t") {
		res.addTag("SUBJECT_ENDS_SPACES")
	}
	if subject == gtubeSubject {
		res.addTag("GTUBE_TEST")
	}
	normalized := normalizeThreadSubject(subject)
	if subjectAllCaps(normalized) {
		res.addTag("SUBJ_ALL_CAPS")
	}
	if subjectHasCurrency(normalized) {
		res.addTag("SUBJECT_HAS_CURRENCY")
	}
	if strings.Contains(strings.ToLower(normalized), "http://") || strings.Contains(strings.ToLower(normalized), "https://") {
		res.addTag("URL_IN_SUBJECT")
	}
}

// normalizeThreadSubject removes repeated standard reply/forward prefixes.
func normalizeThreadSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	for {
		lower := strings.ToLower(subject)
		matched := false
		for _, prefix := range []string{"re:", "fw:", "fwd:"} {
			if strings.HasPrefix(lower, prefix) {
				subject = strings.TrimSpace(subject[len(prefix):])
				matched = true
				break
			}
		}
		if !matched {
			return subject
		}
	}
}

// subjectAllCaps matches reference: len>=10, >1 word, >2 upper, no lower letters.
func subjectAllCaps(subject string) bool {
	if len(subject) < 10 {
		return false
	}
	wordCount := 0
	upper := 0
	lower := 0
	lastSpace := true
	for _, r := range subject {
		if unicode.IsSpace(r) {
			lastSpace = true
			continue
		}
		if lastSpace {
			wordCount++
			lastSpace = false
		}
		if unicode.IsLetter(r) {
			if unicode.IsUpper(r) {
				upper++
			} else {
				lower++
			}
		}
	}
	return wordCount > 1 && upper > 2 && lower == 0
}

func subjectHasCurrency(subject string) bool {
	for _, r := range subject {
		switch r {
		case '$', '€', '£', '¥', '₹', '₽', '₿':
			return true
		}
	}
	return false
}
