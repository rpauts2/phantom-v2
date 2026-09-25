package mailer

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP — минимальный сервер: EHLO/AUTH/MAIL/RCPT/DATA/QUIT, складывает письма.
type fakeSMTP struct {
	mu   sync.Mutex
	mail []string
}

func (f *fakeSMTP) serve(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	say := func(s string) { _, _ = w.WriteString(s + "\r\n"); _ = w.Flush() }
	say("220 fake")
	var data bytes.Buffer
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case inData && line == ".":
			inData = false
			f.mu.Lock()
			f.mail = append(f.mail, data.String())
			f.mu.Unlock()
			data.Reset()
			say("250 ok")
		case inData:
			data.WriteString(line + "\n")
		case strings.HasPrefix(up, "EHLO") || strings.HasPrefix(up, "HELO"):
			say("250-fake")
			say("250 AUTH PLAIN LOGIN")
		case strings.HasPrefix(up, "AUTH"):
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM"):
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO"):
			say("250 ok")
		case strings.HasPrefix(up, "DATA"):
			inData = true
			say("354 go")
		case strings.HasPrefix(up, "QUIT"):
			say("221 bye")
			return
		case strings.HasPrefix(up, "RSET"):
			say("250 ok")
		default:
			say("250 ok")
		}
	}
}

func TestSendReal(t *testing.T) {
	f := &fakeSMTP{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go f.serve(l)

	s := &Sender{Cfg: Config{
		Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port,
		User: "u", Pass: "p", From: "it@corp.test", FromName: "IT",
		DryRun: false,
	}}
	err = s.Send(Mail{
		To: "victim@corp.test", Subject: "Reset for {{.Email}}",
		Body: `<a href="{{.URL}}">reset</a>`, URL: "https://x.test/l/1", Email: "victim@corp.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mail) != 1 {
		t.Fatalf("mails=%d", len(f.mail))
	}
	for _, want := range []string{"victim@corp.test", "Reset for victim@corp.test", "https://x.test/l/1", "IT <it@corp.test>"} {
		if !strings.Contains(f.mail[0], want) {
			t.Fatalf("missing %q in:\n%s", want, f.mail[0])
		}
	}
}

func TestDryRun(t *testing.T) {
	var buf bytes.Buffer
	s := &Sender{Cfg: Config{DryRun: true}, Out: &buf}
	if err := s.Send(Mail{To: "a@b.c", Subject: "hi {{.Email}}", Body: "x", Email: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "DRY to=a@b.c") {
		t.Fatalf("dry log: %q", buf.String())
	}
	if err := (&Sender{Cfg: Config{}}).Send(Mail{To: "a@b.c", Subject: "x", Body: "x"}); err == nil {
		t.Fatal("no creds + no dry must fail")
	}
}
