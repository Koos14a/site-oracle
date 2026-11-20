#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Execute com sudo: sudo bash oracle/setup_ubuntu.sh"
  exit 1
fi

APP_SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="/opt/smartchamados"
DATA_DIR="/var/lib/smartchamados"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip nginx ufw unzip openssl

id smartchamados >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin smartchamados
install -d -o root -g root -m 0755 "$APP_DIR"
install -d -o smartchamados -g www-data -m 0750 "$DATA_DIR" "$DATA_DIR/uploads"
cp "$APP_SRC/app.py" "$APP_SRC/requirements.txt" "$APP_DIR/"
cp -a "$APP_SRC/portal" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
chown -R root:root "$APP_DIR"
chmod -R a+rX "$APP_DIR"

if [[ ! -f /etc/smartchamados.env ]]; then
  TECH_PASS="$(openssl rand -hex 24)"
  cat > /etc/smartchamados.env <<EOF
CHAMADOS_DATA=$DATA_DIR
CHAMADOS_SENHA=$TECH_PASS
CHAMADOS_TECNICO=Suporte TI
CHAMADOS_PROXY=1
CHAMADOS_URL=
TELEGRAM_TOKEN=
TELEGRAM_CHAT_ID=
PORT=8080
EOF
  chmod 600 /etc/smartchamados.env
  echo "Senha inicial da área técnica (guarde em local seguro): $TECH_PASS"
else
  echo "Mantive /etc/smartchamados.env existente."
fi

cat > /etc/systemd/system/smartchamados.service <<EOF
[Unit]
Description=SmartChamados Flask application
After=network.target

[Service]
Type=simple
User=smartchamados
Group=www-data
WorkingDirectory=$APP_DIR
EnvironmentFile=/etc/smartchamados.env
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/app.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/nginx/sites-available/smartchamados <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
EOF
ln -sfn /etc/nginx/sites-available/smartchamados /etc/nginx/sites-enabled/smartchamados
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx
systemctl daemon-reload
systemctl enable smartchamados

ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable

echo
echo "Instalacao base concluida. O SmartChamados ainda NAO foi iniciado."
echo "1) Restaure chamados.db, uploads/ e secret.key em $DATA_DIR."
echo "2) Execute: chown -R smartchamados:www-data $DATA_DIR && chmod 750 $DATA_DIR"
echo "3) Execute: systemctl start smartchamados"
echo "4) Teste: systemctl status smartchamados"
echo "O Nginx ja esta configurado na porta 80; libere TCP 80 e 443 na VCN da Oracle."
