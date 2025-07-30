# VPS Monitoring Panel - Инструкция по установке и настройке

## Обзор системы

Данная система представляет собой веб-панель для мониторинга и управления вашими VPS серверами. Панель устанавливается на московский сервер (194.67.207.234) и позволяет:

- Отслеживать состояние всех серверов (онлайн/офлайн)
- Мониторить загрузку CPU, RAM, диска
- Просматривать системные логи
- Выполнять команды управления (перезагрузка, выключение, перезапуск VPN)
- Безопасный доступ через HTTPS с аутентификацией

## Архитектура

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Ваш браузер   │───▶│  Nginx (HTTPS)   │───▶│ Flask App :8080 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
                                                         ▼
                                               ┌─────────────────┐
                                               │  SSH подключения │
                                               │  к VPS серверам  │
                                               └─────────────────┘
```

## Предварительные требования

1. **Доступ к серверу**
2. **Root права** на сервере
3. **Открытые порты**: 80, 443, 8080
4. **DuckDNS домен**: {domain}.duckdns.org

## Пошаговая установка

### Шаг 1: Подключение к серверу

```bash
ssh root@{ip} -p {port} -i {path/to/key}
```

### Шаг 2: Создание рабочей директории

```bash
mkdir -p /opt/admin-panel-vpn
cd /opt/admin-panel-vpn
```

### Шаг 3: Загрузка файлов приложения

Создайте следующие файлы в директории `/opt/admin-panel-vpn`:

1. **app.py** - основное Flask приложение
2. **requirements.txt** - зависимости Python
3. **templates/base.html** - базовый шаблон
4. **templates/login.html** - страница входа
5. **templates/dashboard.html** - главная панель

### Шаг 4: Создание структуры директорий

```bash
mkdir -p templates
mkdir -p /root/.ssh
chmod 700 /root/.ssh
```

### Шаг 5: Установка SSH ключа

```bash
cat > /root/.ssh/your-key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /root/.ssh/your-key
```

### Шаг 6: Обновление системы и установка пакетов

```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip nginx certbot python3-certbot-nginx ufw fail2ban git
```

### Шаг 7: Установка Python зависимостей

```bash
cd /opt/admin-panel-vpn
pip3 install -r requirements.txt
```

### Шаг 8: Настройка брандмауэра (UFW)

```bash
ufw --force enable
ufw allow ssh
ufw allow 'Nginx Full'
ufw allow 8080
ufw status
```

### Шаг 9: Настройка fail2ban

```bash
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = 5555

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
action = iptables-multiport[name=ReqLimit, port="http,https", protocol=tcp]
logpath = /var/log/nginx/error.log
findtime = 600
bantime = 7200
maxretry = 10
EOF

systemctl enable fail2ban
systemctl restart fail2ban
```

### Шаг 10: Создание systemd сервиса

```bash
cat > /etc/systemd/system/admin-panel-vpn.service << 'EOF'
[Unit]
Description=VPS Monitoring Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/admin-panel-vpn
Environment=PATH=/opt/admin-panel-vpn
ExecStart=/usr/bin/python3 /opt/admin-panel-vpn/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable admin-panel-vpn.service
```

### Шаг 11: Настройка Nginx

```bash
cat > /etc/nginx/sites-available/admin-panel-vpn << 'EOF'
server {
    listen 80;
    server_name {domain}.duckdns.org;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name {domain}.duckdns.org;

    ssl_certificate /etc/letsencrypt/live/{domain}.duckdns.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}.duckdns.org/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    access_log /var/log/nginx/admin-panel-vpn.access.log;
    error_log /var/log/nginx/admin-panel-vpn.error.log;
}
EOF

# Активируем конфигурацию
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/admin-panel-vpn /etc/nginx/sites-enabled/
nginx -t
```

### Шаг 12: Получение SSL сертификата

```bash
# Сначала обновляем DuckDNS
curl "https://www.duckdns.org/update?domains={domain}&token={token}"

# Получаем сертификат
certbot --nginx -d {domain}.duckdns.org --non-interactive --agree-tos --email your@mail,cc

# Настройка автообновления
crontab -l | { cat; echo "0 12 * * * /usr/bin/certbot renew --quiet"; } | crontab -
```

### Шаг 13: Запуск сервисов

```bash
systemctl start admin-panel-vpn
systemctl restart nginx
```

### Шаг 14: Проверка работы

```bash
# Проверяем статус сервисов
systemctl status admin-panel-vpn
systemctl status nginx

# Проверяем логи
journalctl -u admin-panel-vpn -f
```

## Доступ к панели

После успешной установки панель будет доступна по вашему адресу

## Конфигурация других серверов

На остальных VPS серверах убедитесь, что открыты необходимые порты для SSH:

```bash
# На каждом сервере выполните:
ufw allow 5555/tcp
systemctl restart ufw
```

## Функции панели

### Мониторинг
- **Статус серверов**: онлайн/офлайн индикаторы
- **Загрузка CPU**: процентное использование процессора
- **Использование RAM**: процент занятой оперативной памяти
- **Использование диска**: процент занятого места на диске
- **Системная нагрузка**: load average
- **Время работы**: uptime серверов
- **Автообновление**: каждые 30 секунд

### Управление серверами
- **Перезапуск VPN**: перезапуск Amnezia VPN сервиса
- **Перезагрузка**: полная перезагрузка сервера
- **Выключение**: корректное выключение сервера
- **Просмотр логов**: последние 50 строк системных логов

### Безопасность
- **HTTPS**: принудительное использование SSL
- **Аутентификация**: обязательный вход в систему
- **Rate limiting**: ограничение количества запросов
- **Fail2ban**: автоблокировка подозрительных IP
- **UFW**: настроенный брандмауэр
- **Безопасные заголовки**: защита от XSS и других атак

## Управление и обслуживание

### Полезные команды

```bash
# Перезапуск панели
systemctl restart admin-panel-vpn

# Просмотр логов панели
journalctl -u admin-panel-vpn -f

# Просмотр логов Nginx