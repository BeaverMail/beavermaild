package mailauth

import "strings"

// AuthResults returns the value of an RFC 8601 Authentication-Results header for the
// checks recorded in st (folded, without the field name), e.g.
//
//	mx.example.com;
//		spf=pass smtp.mailfrom=a@example.org;
//		dkim=pass header.d=example.org;
//		dmarc=pass header.from=example.org
//
// mailFrom is the envelope sender ("" for a null sender, then SPF is reported for helo).
func AuthResults(authservID, mailFrom, helo string, st SessionState) string {
	var methods []string
	switch {
	case mailFrom != "" && st.SPFMailFrom != "":
		methods = append(methods, "spf="+st.SPFMailFrom+" smtp.mailfrom="+mailFrom)
	case st.SPFEhlo != "" && helo != "":
		methods = append(methods, "spf="+st.SPFEhlo+" smtp.helo="+helo)
	}
	if st.DKIM != "" {
		m := "dkim=" + st.DKIM
		if st.DKIMDomain != "" {
			m += " header.d=" + st.DKIMDomain
		}
		methods = append(methods, m)
	}
	if st.DMARC != "" {
		m := "dmarc=" + st.DMARC
		if st.DMARCPolicy != "" {
			m += " (p=" + st.DMARCPolicy + ")"
		}
		if st.FromDomain != "" {
			m += " header.from=" + st.FromDomain
		}
		methods = append(methods, m)
	}
	if st.ARC != "" {
		methods = append(methods, "arc="+st.ARC)
	}
	if len(methods) == 0 {
		return authservID + "; none" // RFC 8601 §2.2: no method was applied
	}
	return authservID + ";\r\n\t" + strings.Join(methods, ";\r\n\t")
}
