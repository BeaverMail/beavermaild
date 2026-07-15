// Auth tag mapping at classify (reference analysis/dmarc.rs).
package main

func analyzeAuth(ctx *classifyCtx, res *classifyResult) {
	if ctx.req.Auth == nil {
		return
	}
	res.addTags(authTags(ctx.req.Auth))
}

func authTags(a *wireAuth) []string {
	var tags []string
	if a.SPFEhlo != "" {
		tags = append(tags, spfTag(a.SPFEhlo)...)
	}
	if a.SPFMailFrom != "" {
		tags = append(tags, spfTag(a.SPFMailFrom)...)
	}
	if a.DKIM != "" {
		tags = append(tags, dkimTag(a.DKIM)...)
	}
	if a.DMARC != "" {
		tags = append(tags, dmarcTag(a.DMARC, a.DMARCPolicy)...)
	}
	if a.ARC != "" {
		tags = append(tags, arcTag(a.ARC)...)
	}
	return tags
}

// arcTag maps an RFC 8617 chain validation result to a spam tag.
func arcTag(result string) []string {
	switch result {
	case "pass":
		return []string{"ARC_ALLOW"}
	case "fail":
		return []string{"ARC_REJECT"}
	case "invalid":
		return []string{"ARC_INVALID"}
	case "temperror":
		return []string{"ARC_DNSFAIL"}
	default:
		return []string{"ARC_NA"}
	}
}

func spfTag(result string) []string {
	switch result {
	case "pass":
		return []string{"SPF_ALLOW"}
	case "fail":
		return []string{"SPF_FAIL"}
	case "softfail":
		return []string{"SPF_SOFTFAIL"}
	case "neutral":
		return []string{"SPF_NEUTRAL"}
	case "temperror":
		return []string{"SPF_DNSFAIL"}
	case "permerror":
		return []string{"SPF_PERMFAIL"}
	case "none", "":
		return []string{"SPF_NA"}
	default:
		return nil
	}
}

func dkimTag(result string) []string {
	switch result {
	case "pass":
		return []string{"DKIM_ALLOW"}
	case "fail":
		return []string{"DKIM_REJECT"}
	case "permerror":
		return []string{"DKIM_PERMFAIL"}
	case "temperror":
		return []string{"DKIM_TEMPFAIL"}
	default:
		return []string{"DKIM_NA"}
	}
}

func dmarcTag(result, policy string) []string {
	switch result {
	case "pass":
		return []string{"DMARC_POLICY_ALLOW"}
	case "fail":
		switch policy {
		case "reject":
			return []string{"DMARC_POLICY_REJECT"}
		case "quarantine":
			return []string{"DMARC_POLICY_QUARANTINE"}
		default:
			return []string{"DMARC_POLICY_SOFTFAIL"}
		}
	case "temperror":
		return []string{"DMARC_DNSFAIL"}
	case "permerror":
		return []string{"DMARC_BAD_POLICY"}
	default:
		return []string{"DMARC_NA"}
	}
}
