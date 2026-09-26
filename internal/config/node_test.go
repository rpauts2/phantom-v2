package config

import "testing"

func TestNodeID(t *testing.T) {
	c, err := Load(writeTemp(t, valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.NodeID == "" {
		t.Fatal("node must default (hostname)")
	}
	t.Setenv("PHANTOM_NODE_ID", "eu-1")
	c2, err := Load(writeTemp(t, valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c2.NodeID != "eu-1" {
		t.Fatalf("env override: %q", c2.NodeID)
	}
}

func TestAutocertDefault(t *testing.T) {
	c, err := Load(writeTemp(t, valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.TLS.Autocert == nil || !*c.TLS.Autocert {
		t.Fatal("autocert must default ON")
	}
}

func TestNameDefaults(t *testing.T) {
	c, err := Load(writeTemp(t, valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.SessCookie != "sid" || c.ChallPath != "/__fp" {
		t.Fatalf("defaults: %+v", c)
	}
}
