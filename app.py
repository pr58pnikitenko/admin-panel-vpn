from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import paramiko
import psutil
import threading
import time
import json
from datetime import datetime
import subprocess
import os
from functools import wraps
import requests

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Конфигурация серверов
SERVERS = {
    'server-name': {
        'host': '',
        'port': 0,
        'name': '',
        'location': ''
    },
}

# Креденшалы для входа
LOGIN_CREDENTIALS = {
    'username': '',
    'password': ''
}

# Путь к SSH ключу
SSH_KEY_PATH = 'path/to/key'

# DuckDNS конфигурация
DUCKDNS_DOMAIN = '{domain}.duckdns.org'
DUCKDNS_TOKEN = '{duckdns_token}'

# Глобальные переменные для хранения состояния серверов
server_status = {}
server_stats = {}


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def create_ssh_connection(server_id):
    """Создает SSH соединение с сервером"""
    try:
        server = SERVERS[server_id]
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Загружаем приватный ключ
        private_key = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)

        ssh.connect(
            hostname=server['host'],
            port=server['port'],
            username='root',
            pkey=private_key,
            timeout=10
        )
        return ssh
    except Exception as e:
        print(f"SSH connection error for {server_id}: {str(e)}")
        return None


def get_server_stats(server_id):
    """Получает статистику сервера через SSH"""
    ssh = create_ssh_connection(server_id)
    if not ssh:
        return None

    try:
        # Команды для получения статистики
        commands = {
            'cpu': "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
            'memory': "free -m | awk 'NR==2{printf \"%.1f\", $3*100/$2 }'",
            'disk': "df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1",
            'uptime': "uptime -p",
            'load': "uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | cut -d',' -f1",
            'network_rx': "cat /proc/net/dev | grep eth0 | awk '{print $2}'",
            'network_tx': "cat /proc/net/dev | grep eth0 | awk '{print $10}'",
            'processes': "ps aux | wc -l"
        }

        stats = {}
        for key, command in commands.items():
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode().strip()
            stats[key] = output

        ssh.close()
        return stats
    except Exception as e:
        print(f"Error getting stats for {server_id}: {str(e)}")
        ssh.close()
        return None


def check_server_status(server_id):
    """Проверяет доступность сервера"""
    try:
        ssh = create_ssh_connection(server_id)
        if ssh:
            ssh.close()
            return True
        return False
    except:
        return False


def monitor_servers():
    """Фоновая задача для мониторинга серверов"""
    while True:
        for server_id in SERVERS.keys():
            server_status[server_id] = check_server_status(server_id)
            if server_status[server_id]:
                server_stats[server_id] = get_server_stats(server_id)
            else:
                server_stats[server_id] = None
        time.sleep(30)  # Обновляем каждые 30 секунд


def update_duckdns():
    """Обновляет DuckDNS с текущим IP"""
    try:
        # Получаем внешний IP
        response = requests.get('https://api.ipify.org?format=json', timeout=10)
        current_ip = response.json()['ip']

        # Обновляем DuckDNS
        duckdns_url = f"https://www.duckdns.org/update?domains={DUCKDNS_DOMAIN}&token={DUCKDNS_TOKEN}&ip={current_ip}"
        response = requests.get(duckdns_url, timeout=10)

        if response.text.strip() == 'OK':
            print(f"DuckDNS updated successfully with IP: {current_ip}")
        else:
            print(f"DuckDNS update failed: {response.text}")
    except Exception as e:
        print(f"Error updating DuckDNS: {str(e)}")


@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', servers=SERVERS)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if (username == LOGIN_CREDENTIALS['username'] and
                password == LOGIN_CREDENTIALS['password']):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Неверные учетные данные')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/api/status')
@login_required
def api_status():
    """API для получения статуса всех серверов"""
    return jsonify({
        'status': server_status,
        'stats': server_stats,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/server/<server_id>/action/<action>', methods=['POST'])
@login_required
def server_action(server_id, action):
    """API для управления серверами"""
    if server_id not in SERVERS:
        return jsonify({'error': 'Server not found'}), 404

    ssh = create_ssh_connection(server_id)
    if not ssh:
        return jsonify({'error': 'Cannot connect to server'}), 500

    try:
        commands = {
            'reboot': 'sudo reboot',
            'shutdown': 'sudo shutdown -h now',
            'restart_vpn': 'docker restart amnezia-awg',
            'update_system': 'apt update && apt upgrade -y'
        }

        if action not in commands:
            return jsonify({'error': 'Invalid action'}), 400

        stdin, stdout, stderr = ssh.exec_command(commands[action])

        # Для перезагрузки и выключения не ждем ответа
        if action in ['reboot', 'shutdown']:
            ssh.close()
            return jsonify({'success': True, 'message': f'{action} command sent'})

        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()

        if error:
            return jsonify({'error': error}), 500

        return jsonify({'success': True, 'output': output})

    except Exception as e:
        ssh.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/server/<server_id>/logs')
@login_required
def server_logs(server_id):
    """API для получения логов сервера"""
    if server_id not in SERVERS:
        return jsonify({'error': 'Server not found'}), 404

    ssh = create_ssh_connection(server_id)
    if not ssh:
        return jsonify({'error': 'Cannot connect to server'}), 500

    try:
        # Получаем последние 50 строк системных логов
        stdin, stdout, stderr = ssh.exec_command('tail -n 50 /var/log/syslog')
        logs = stdout.read().decode()
        ssh.close()

        return jsonify({'logs': logs})
    except Exception as e:
        ssh.close()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Обновляем DuckDNS при запуске
    update_duckdns()

    # Запускаем мониторинг в отдельном потоке
    monitor_thread = threading.Thread(target=monitor_servers, daemon=True)
    monitor_thread.start()

    # Запускаем Flask приложение
    app.run(host='0.0.0.0', port=8080, debug=False)