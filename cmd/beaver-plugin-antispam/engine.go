// SMTP filter engine for beaver-plugin-antispam.
package main

import (
	"os"
	"regexp"
	"sync"
)

type engine struct {
	store   *configStore
	static  *staticLists
	lists   *lookupLists
	rbl     *rblChecker
	content *contentRules
	rules   []exprRule
	tags    map[string][]string
	mu      sync.Mutex
}

func newEngine(dataDir string) (*engine, error) {
	store, err := newConfigStore(dataDir)
	if err != nil {
		return nil, err
	}
	e := &engine{
		store:   store,
		static:  newStaticLists(dataDir),
		lists:   newLookupLists(),
		rbl:     newRBLChecker(),
		content: newContentRules(),
		tags:    make(map[string][]string),
	}
	e.reloadDeps()
	return e, nil
}

func (e *engine) reloadDeps() {
	cfg := e.store.get()
	e.static.reload(cfg, e.store.dataDir)
	e.lists.reload(cfg, e.store.dataDir)
	e.content.reload(cfg)
	e.rules = compileRules(cfg)
}

func (e *engine) maybeReload() {
	e.store.maybeReload()
	e.reloadDeps()
}

func (e *engine) handle(req filterReq) filterResp {
	cfg := e.store.get()
	if !cfg.Enabled {
		return filterResp{ID: req.ID, Action: "accept"}
	}
	if cfg.SkipAuthenticated && req.Authenticated {
		return filterResp{ID: req.ID, Action: "accept"}
	}

	switch req.Phase {
	case "connect":
		return e.handleConnect(req, cfg)
	case "helo":
		return e.handleHelo(req, cfg)
	case "mail":
		return e.handleMail(req, cfg)
	case "rcpt":
		return e.handleRcpt(req, cfg)
	case "eom":
		return e.handleEom(req, cfg)
	default:
		return filterResp{ID: req.ID, Action: "accept"}
	}
}

func (e *engine) handleConnect(req filterReq, cfg pluginConfig) filterResp {
	if cfg.HardReject.StaticOnConnect {
		if e.static.deniesIP(req.ClientIP) {
			return filterResp{ID: req.ID, Action: "reject", Tags: []string{cfg.Static.tag("client_ip")}}
		}
	}
	if cfg.RBL.Enabled {
		listed, tag, dnsFail := e.rbl.checkIPStr(req.ClientIP, cfg.RBL.forScope("client_ip"))
		if dnsFail && cfg.RBL.OnDNSFail == "tempfail" {
			return filterResp{ID: req.ID, Action: "tempfail"}
		}
		if listed && tag != "" {
			if cfg.HardReject.RBLOnConnect {
				e.addTag(req.ID, tag)
				return filterResp{ID: req.ID, Action: "reject", Tags: []string{tag}}
			}
			e.addTag(req.ID, tag)
		}
	}
	return filterResp{ID: req.ID, Action: "accept"}
}

func (e *engine) handleHelo(req filterReq, cfg pluginConfig) filterResp {
	var res classifyResult
	ctx := &classifyCtx{req: req, cfg: cfg, msg: &parsedMessage{}}
	analyzeEHLO(ctx, &res)
	for _, tag := range res.tags {
		if act := cfg.TagActions[tag]; act == "reject" || act == "discard" {
			return filterResp{ID: req.ID, Action: act, Tags: uniqueTags(res.tags), Score: scoreFor(res.tags, cfg.Scores)}
		}
	}
	return filterResp{ID: req.ID, Action: "accept"}
}

func (e *engine) handleMail(req filterReq, cfg pluginConfig) filterResp {
	if e.static.deniesFrom(req.From) {
		tag := cfg.Static.tag("mail_from")
		if act := cfg.TagActions[tag]; act != "" {
			return filterResp{ID: req.ID, Action: act, Tags: []string{tag}}
		}
		e.addTag(req.ID, tag)
	}
	return filterResp{ID: req.ID, Action: "accept"}
}

func (e *engine) handleRcpt(req filterReq, cfg pluginConfig) filterResp {
	for _, to := range req.To {
		if e.static.deniesRcpt(to) {
			tag := cfg.Static.tag("rcpt_to")
			if act := cfg.TagActions[tag]; act != "" {
				return filterResp{ID: req.ID, Action: act, Tags: []string{tag}}
			}
			e.addTag(req.ID, tag)
		}
	}
	return filterResp{ID: req.ID, Action: "accept"}
}

func (e *engine) handleEom(req filterReq, cfg pluginConfig) filterResp {
	early := e.takeTags(req.ID)
	ctx, err := newClassifyCtx(req, cfg, early, e.content, e.lists, e.rules)
	if err != nil {
		return filterResp{ID: req.ID, Action: "accept"}
	}
	result := runClassify(ctx, e)
	return finalizeClassify(req.ID, result.tags, cfg)
}

func (e *engine) addTag(id, tag string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tags[id] = append(e.tags[id], tag)
}

func (e *engine) takeTags(id string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.tags[id]
	delete(e.tags, id)
	return t
}

type contentRules struct {
	mu       sync.RWMutex
	patterns []*regexp.Regexp
	maxBytes int
}

func newContentRules() *contentRules { return &contentRules{} }

func (c *contentRules) reload(cfg pluginConfig) {
	var pats []*regexp.Regexp
	for _, s := range cfg.Content.DenySubjectRegex {
		if re, err := regexp.Compile(s); err == nil {
			pats = append(pats, re)
		}
	}
	max := cfg.Content.MaxHeaderBytes
	if max <= 0 {
		max = 65536
	}
	c.mu.Lock()
	c.patterns = pats
	c.maxBytes = max
	c.mu.Unlock()
}

func (c *contentRules) matchSubject(bodyPath string) (bool, error) {
	c.mu.RLock()
	pats := c.patterns
	max := c.maxBytes
	c.mu.RUnlock()
	if len(pats) == 0 || bodyPath == "" {
		return false, nil
	}
	b, err := osReadFileLimit(bodyPath, max)
	if err != nil {
		return false, err
	}
	subject := extractSubject(b)
	for _, re := range pats {
		if re.MatchString(subject) {
			return true, nil
		}
	}
	return false, nil
}

func osReadFileLimit(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, max)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}
