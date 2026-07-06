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
	if subjectAllCaps(subject) {
		res.addTag("SUBJ_ALL_CAPS")
	}
	if subjectHasCurrency(subject) {
		res.addTag("SUBJECT_HAS_CURRENCY")
	}
	if strings.Contains(strings.ToLower(subject), "http://") || strings.Contains(strings.ToLower(subject), "https://") {
		res.addTag("URL_IN_SUBJECT")
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
