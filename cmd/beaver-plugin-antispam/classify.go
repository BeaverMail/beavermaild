// Classify context and analyzer orchestration (reference spam-filter order).
package main

type filterReq struct {
	ID            string    `json:"id"`
	Phase         string    `json:"phase"`
	From          string    `json:"from"`
	To            []string  `json:"to"`
	ClientIP      string    `json:"client_ip"`
	BodyPath      string    `json:"body_path"`
	Listener      string    `json:"listener"`
	TLS           bool      `json:"tls"`
	Authenticated bool      `json:"authenticated"`
	EHLODomain    string    `json:"ehlo_domain"`
	IPRevPTR      string    `json:"iprev_ptr"`
	IPRevResult   string    `json:"iprev_result"`
	ASN           uint32    `json:"asn"`
	Country       string    `json:"country"`
	Auth          *wireAuth `json:"auth"`
}

type wireAuth struct {
	SPFEhlo     string `json:"spf_ehlo"`
	SPFMailFrom string `json:"spf_mail_from"`
	DKIM        string `json:"dkim"`
	DMARC       string `json:"dmarc"`
	DMARCPolicy string `json:"dmarc_policy"`
	ARC         string `json:"arc"`
}

type filterResp struct {
	ID      string            `json:"id"`
	Action  string            `json:"action"`
	Score   float64           `json:"score,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// classifyCtx holds per-transaction state for eom analyzers.
type classifyCtx struct {
	req            filterReq
	cfg            pluginConfig
	msg            *parsedMessage
	body           *messageBody
	harvest        *harvestSet
	early          []string
	maxHeaderBytes int
	content        *contentRules
	lists          *lookupLists
	rules          []exprRule
	rblBudget      *rblBudget
}

// classifyResult accumulates tags during analyze pass.
type classifyResult struct {
	tags []string
}

func (r *classifyResult) addTag(tag string) {
	if tag == "" {
		return
	}
	r.tags = append(r.tags, tag)
}

func (r *classifyResult) addTags(tags []string) {
	for _, t := range tags {
		r.addTag(t)
	}
}

// runClassify runs eom analyzers in reference order (LLM, ML, Pyzor skipped per spec).
func runClassify(ctx *classifyCtx, eng *engine) classifyResult {
	var res classifyResult
	res.addTags(ctx.early)

	analyzeIP(ctx, &res, eng)
	analyzeAuth(ctx, &res)
	analyzeEHLO(ctx, &res)
	analyzeHeaders(ctx, &res)
	analyzeReceived(ctx, &res)
	analyzeMessageID(ctx, &res)
	analyzeDate(ctx, &res)
	analyzeSubject(ctx, &res)
	analyzeSubjectRegex(ctx, &res)
	analyzeFrom(ctx, &res)
	analyzeReplyTo(ctx, &res)
	analyzeRecipient(ctx, &res)
	analyzeDomain(ctx, &res, eng)
	analyzeURL(ctx, &res, eng)
	analyzeMIME(ctx, &res)
	analyzeHTML(ctx, &res)
	analyzeSpamTrap(ctx, &res)
	analyzeRules(ctx, &res, ctx.rules)

	return res
}

func newClassifyCtx(req filterReq, cfg pluginConfig, early []string, content *contentRules, lists *lookupLists, rules []exprRule) (*classifyCtx, error) {
	max := cfg.Content.MaxHeaderBytes
	if max <= 0 {
		max = 65536
	}
	ctx := &classifyCtx{
		req:            req,
		cfg:            cfg,
		early:          early,
		maxHeaderBytes: max,
		content:        content,
		lists:          lists,
		rules:          rules,
		rblBudget:      newRBLBudget(cfg.RBL.MaxChecksPerMessage),
	}
	if req.BodyPath != "" {
		msg, err := loadParsedMessage(req.BodyPath, max)
		if err != nil {
			return nil, err
		}
		ctx.msg = msg
		body, harvest, err := loadMessageBody(req.BodyPath)
		if err == nil {
			ctx.body = body
			ctx.harvest = harvest
		} else {
			ctx.harvest = newHarvestSet()
		}
	} else {
		ctx.msg = &parsedMessage{headers: make(map[string][]string)}
		ctx.harvest = newHarvestSet()
	}
	return ctx, nil
}
