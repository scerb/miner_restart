import os
import sys
import json
import time
import requests
import subprocess
import logging
import signal
from datetime import datetime, timedelta
from packaging import version
import argparse
import threading
from flask import Flask, request, jsonify
from typing import Optional, Dict, Any, Set, List

__version__ = "1.0.0"

# Configuration paths
APP_FOLDER = os.path.dirname(os.path.abspath(__file__))
ADDRESS_FILE = os.path.join(APP_FOLDER, "addresses.json")
PING_LOG_FILE = os.path.join(APP_FOLDER, "ping_log.jsonl")  # Using JSON Lines format
UPTIME_FILE = os.path.join(APP_FOLDER, "uptime.json")
NON_DOCKER_SCRIPT = os.path.join(APP_FOLDER, "restart_cortensor.sh")
PING_API_URL = "https://lb-be-4.cortensor.network/leaderboard"
DEFAULT_TIMEOUT = 12  # 12 minutes
MIN_TIMEOUT = 6  # 6 minutes minimum
COOLDOWN_PERIOD = 6 * 60  # 6 minutes in seconds
ALERT_SETTINGS_FILE = os.path.join(APP_FOLDER, "alert_settings.json")
SENT_ALERTS_FILE = os.path.join(APP_FOLDER, "sent_alerts.json")
GITHUB_REPO = "https://api.github.com/repos/scerb/miner_restart/releases/latest"
SUDOERS_FILE = "/etc/sudoers.d/cortensor_monitor"
CONFIG_FILE = os.path.join(APP_FOLDER, "config.json")
CONTROL_SERVER_PORT = 5000  # Port for the control server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(APP_FOLDER, 'monitor.log')),
        logging.StreamHandler()
    ]
)

class TelegramNotifier:
    def __init__(self, settings_file: str, sent_alerts_file: str):
        self.settings_file = settings_file
        self.sent_alerts_file = sent_alerts_file
        self.settings = self._load_json(settings_file)
        self.sent_alerts: Set[str] = self._load_json_set(sent_alerts_file)

    def _load_json(self, path: str) -> dict:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_json_set(self, path: str) -> Set[str]:
        try:
            with open(path, 'r') as f:
                return set(json.load(f))
        except Exception:
            return set()

    def _save_json_set(self, data_set: Set[str]) -> None:
        try:
            with open(self.sent_alerts_file, 'w') as f:
                json.dump(list(data_set), f, indent=2)
        except Exception as e:
            logging.error(f"Error saving alerts: {e}")

    def send(self, message: str, skip_duplicate_check: bool = False) -> bool:
        if not self.settings.get("telegram_enabled", False):
            logging.debug("Telegram alerts are disabled")
            return False

        bot_token = self.settings.get("bot_token", "").strip()
        chat_id = self.settings.get("chat_id", "").strip()

        if not bot_token or not chat_id:
            logging.warning("Telegram bot token or chat ID is missing")
            return False

        if not skip_duplicate_check and message in self.sent_alerts:
            logging.info(f"Skipping duplicate alert: {message}")
            return False

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        params = {'chat_id': chat_id, 'text': message}

        try:
            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                logging.info(f"Telegram alert sent: {message}")
                self.sent_alerts.add(message)
                self._save_json_set(self.sent_alerts)
                return True
            logging.error(f"Telegram API error {response.status_code}: {response.text}")
            return False
        except Exception as e:
            logging.error(f"Failed to send Telegram alert: {e}")
            return False

    def test(self) -> bool:
        return self.send("Test alert from Cortensor Monitor", skip_duplicate_check=True)

class UptimeTracker:
    """Robust uptime tracking system with atomic writes"""
    def __init__(self, uptime_file: str):
        self.uptime_file = uptime_file
        self.data: Dict[str, Dict[str, int]] = {}
        self._load()
    
    def _load(self):
        """Load and validate uptime data"""
        try:
            if os.path.exists(self.uptime_file):
                with open(self.uptime_file, 'r') as f:
                    raw_data = json.load(f)
                    # Convert all timestamps to integers
                    self.data = {
                        addr: {k: int(v) for k, v in timestamps.items()}
                        for addr, timestamps in raw_data.items()
                    }
        except Exception as e:
            logging.error(f"Error loading uptime data: {e}")
            self.data = {}

    def save(self):
        """Save with atomic write operation"""
        try:
            temp_file = f"{self.uptime_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            os.replace(temp_file, self.uptime_file)
        except Exception as e:
            logging.error(f"Error saving uptime data: {e}")

    def record_activity(self, address: str, timestamp: int):
        """Record miner activity with first ping detection"""
        if address not in self.data:
            self.data[address] = {
                'first_ping': timestamp,
                'last_active': timestamp,
                'last_restart': 0
            }
        else:
            self.data[address]['last_active'] = timestamp
        self.save()

    def record_restart(self, address: str, timestamp: int):
        """Record miner restart time"""
        if address not in self.data:
            self.record_activity(address, timestamp)
        self.data[address]['last_restart'] = timestamp
        self.save()

    def get_uptime(self, address: str, current_time: int) -> Optional[int]:
        """Calculate uptime with proper fallback logic"""
        if address not in self.data:
            return None
        
        timestamps = self.data[address]
        
        # Priority: last_restart > first_ping > last_active
        if timestamps.get('last_restart', 0) > 0:
            return current_time - timestamps['last_restart']
        if timestamps.get('first_ping', 0) > 0:
            return current_time - timestamps['first_ping']
        if timestamps.get('last_active', 0) > 0:
            return current_time - timestamps['last_active']
        return None

class PingLogger:
    """Reliable JSON Lines logger"""
    def __init__(self, log_file: str):
        self.log_file = log_file
        self._ensure_file()
    
    def _ensure_file(self):
        """Create empty file if doesn't exist"""
        if not os.path.exists(self.log_file):
            open(self.log_file, 'a').close()

    def log_ping(self, address: str, timestamp: int, status: str):
        """Log ping entry in JSON Lines format"""
        entry = {
            'timestamp': timestamp,
            'address': address,
            'status': status,
            'human_time': datetime.fromtimestamp(timestamp).isoformat()
        }
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logging.error(f"Error writing ping log: {e}")

class ControlServer:
    def __init__(self, monitor):
        self.monitor = monitor
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/restart', methods=['POST'])
        def handle_restart():
            data = request.json
            address = data.get('address')
            all_miners = data.get('all', False)
            
            if all_miners:
                result = []
                for miner in self.monitor.miners:
                    success = self.monitor.restart_miner(miner, manual=True)
                    result.append({
                        'address': miner['address'],
                        'success': success
                    })
                return jsonify({'message': 'Restart initiated for all miners', 'results': result})
            elif address:
                miner = next((m for m in self.monitor.miners if m['address'] == address), None)
                if miner:
                    success = self.monitor.restart_miner(miner, manual=True)
                    return jsonify({
                        'message': f'Restart initiated for miner {address}',
                        'success': success
                    })
                else:
                    return jsonify({'error': 'Miner not found'}), 404
            else:
                return jsonify({'error': 'No address specified and all=False'}), 400

    def run(self):
        self.app.run(host='0.0.0.0', port=CONTROL_SERVER_PORT)

class MinerMonitor:
    def __init__(self):
        self.uptime_tracker = UptimeTracker(UPTIME_FILE)
        self.ping_logger = PingLogger(PING_LOG_FILE)
        self.notifier = TelegramNotifier(ALERT_SETTINGS_FILE, SENT_ALERTS_FILE)
        self.miners = []
        self.config = self._load_config()
        self.running = True
        self.last_display_time = 0
        self.display_interval = 30
        self.last_update_check = 0
        self.update_check_interval = 86400  # 24 hours
        self.control_server = ControlServer(self)
        self.control_thread = None
        self.miner_timeouts = {}
        
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        signal.signal(signal.SIGINT, self.handle_shutdown)
        
        self.load_miners()
        self._init_timeouts()
        self.check_for_updates()  # Initial update check

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration with validation"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {"check_interval": 30, "timeouts": {}}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return {"check_interval": 30, "timeouts": {}}

    def _save_config(self):
        """Save configuration with atomic write"""
        temp_file = f"{CONFIG_FILE}.tmp"
        try:
            with open(temp_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            os.replace(temp_file, CONFIG_FILE)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

    def _init_timeouts(self):
        """Initialize miner timeout settings"""
        for miner in self.miners:
            addr = miner['address']
            self.miner_timeouts[addr] = self.config.get('timeouts', {}).get(addr, DEFAULT_TIMEOUT) * 60

    def _format_timedelta(self, seconds: int) -> str:
        """Convert seconds to human-readable format"""
        delta = timedelta(seconds=seconds)
        if delta.days > 0:
            return f"{delta.days}d {delta.seconds//3600}h"
        hours, remainder = divmod(delta.seconds, 3600)
        minutes = remainder // 60
        return f"{hours}h {minutes}m"

    def handle_shutdown(self, signum, frame):
        logging.info("Shutting down gracefully...")
        self.running = False
        if self.control_thread:
            os._exit(0)

    def load_miners(self):
        if not os.path.exists(ADDRESS_FILE):
            logging.error("No addresses found. Please initialize the monitor first.")
            sys.exit(1)

        try:
            with open(ADDRESS_FILE, 'r') as f:
                self.miners = json.load(f)
            logging.info(f"Loaded {len(self.miners)} miners to monitor")
        except Exception as e:
            logging.error(f"Failed to load miners: {e}")
            sys.exit(1)

    def save_miners(self):
        try:
            temp_file = f"{ADDRESS_FILE}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.miners, f, indent=2)
            os.replace(temp_file, ADDRESS_FILE)
        except Exception as e:
            logging.error(f"Failed to save miners: {e}")

    def check_sudoers_permission(self):
        if not os.path.exists(SUDOERS_FILE):
            return False
        
        try:
            with open(SUDOERS_FILE, 'r') as f:
                return "NOPASSWD: /bin/systemctl" in f.read()
        except Exception as e:
            logging.error(f"Error checking sudoers file: {e}")
            return False

    def update_sudoers(self):
        try:
            username = os.getenv('SUDO_USER') or os.getenv('USER') or subprocess.getoutput("whoami")
            sudoers_content = f"{username} ALL=(ALL) NOPASSWD: /bin/systemctl\n"
            
            temp_file = "/tmp/cortensor_sudoers"
            with open(temp_file, 'w') as f:
                f.write(sudoers_content)
            
            subprocess.run(["sudo", "mv", temp_file, SUDOERS_FILE], check=True)
            subprocess.run(["sudo", "chown", "root:root", SUDOERS_FILE], check=True)
            subprocess.run(["sudo", "chmod", "0440", SUDOERS_FILE], check=True)
            
            logging.info("Sudoers file updated successfully.")
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to update sudoers: {e}\n\nPlease run manually:\n"
            error_msg += f"echo '{username} ALL=(ALL) NOPASSWD: /bin/systemctl' | sudo tee {SUDOERS_FILE} && "
            error_msg += f"sudo chown root:root {SUDOERS_FILE} && sudo chmod 0440 {SUDOERS_FILE}"
            logging.error(error_msg)
            return False
        except Exception as e:
            logging.error(f"Failed to update sudoers: {str(e)}")
            return False

    def display_miner_status(self, miner_data):
        """Display miner status with formatted times"""
        print("\nCurrent Miner Status:")
        print("-" * 95)
        print(f"{'Address':<15} {'Container':<20} {'Status':<10} {'Last Ping':<20} {'Uptime':<15} {'Timeout':<10}")
        print("-" * 95)
        
        now = int(time.time())
        for miner in miner_data:
            addr = miner['address'][:12] + '...' if len(miner['address']) > 15 else miner['address']
            container = miner.get('container_name', 'N/A')[:17] + '...' if len(miner.get('container_name', 'N/A')) > 20 else miner.get('container_name', 'N/A')
            status = miner.get('status', 'Unknown')
            
            # Format last ping
            last_ping = "Never"
            if miner.get('last_active'):
                last_ping_seconds = now - miner['last_active']
                last_ping = f"{last_ping_seconds//60}m {last_ping_seconds%60}s"
            
            # Format uptime
            uptime = "Unknown"
            uptime_seconds = self.uptime_tracker.get_uptime(miner['address'], now)
            if uptime_seconds is not None:
                uptime = f"{uptime_seconds//3600}h {(uptime_seconds%3600)//60}m"
            
            # Format timeout
            timeout_min = self.miner_timeouts.get(miner['address'], DEFAULT_TIMEOUT * 60) // 60
            if status == 'Offline':
                offline_time = now - miner.get('last_active', now)
                timeout_seconds = self.miner_timeouts.get(miner['address'], DEFAULT_TIMEOUT * 60)
                time_left = max(0, timeout_seconds - offline_time)
                timeout_str = f"{time_left//60}m {time_left%60}s"
            else:
                timeout_str = f"{timeout_min}m"
            
            print(f"{addr:<15} {container:<20} {status:<10} {last_ping:<20} {uptime:<15} {timeout_str:<10}")
        print("-" * 95)
        print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    def set_miner_timeout(self, address=None, minutes=None):
        if minutes is None or minutes < MIN_TIMEOUT:
            logging.warning(f"Timeout must be at least {MIN_TIMEOUT} minutes")
            return False
        
        if address:
            self.miner_timeouts[address] = minutes * 60
            if 'timeouts' not in self.config:
                self.config['timeouts'] = {}
            self.config['timeouts'][address] = minutes
            logging.info(f"Updated timeout for {address} to {minutes} minutes")
        else:
            for miner in self.miners:
                addr = miner['address']
                self.miner_timeouts[addr] = minutes * 60
                if 'timeouts' not in self.config:
                    self.config['timeouts'] = {}
                self.config['timeouts'][addr] = minutes
            logging.info(f"Updated timeout for all miners to {minutes} minutes")
        
        self._save_config()
        return True

    def start_control_server(self):
        self.control_thread = threading.Thread(target=self.control_server.run, daemon=True)
        self.control_thread.start()
        logging.info(f"Control server started on port {CONTROL_SERVER_PORT}")

    def monitor_loop(self):
        logging.info("Starting monitoring loop...")
        self.start_control_server()
        
        while self.running:
            try:
                miner_data = self.refresh_data()
                current_time = time.time()
                
                if current_time - self.last_display_time >= self.display_interval:
                    if miner_data:
                        self.display_miner_status(miner_data)
                    self.last_display_time = current_time
                
                self.check_for_updates()
                time.sleep(self.config.get('check_interval', 30))
            except Exception as e:
                logging.error(f"Error in monitor loop: {e}")
                time.sleep(30)

    def refresh_data(self):
        try:
            resp = requests.get(PING_API_URL, timeout=10)
            if resp.status_code != 200:
                logging.error(f"Error fetching ping data (HTTP {resp.status_code})")
                return None
            
            data = resp.json()
            now = int(time.time())
            miner_data = []
            
            for miner in self.miners:
                addr = miner['address']
                matched = next((x for x in data if x.get("miner") == addr), None)
                
                if not matched:
                    logging.warning(f"Miner {addr} not found in leaderboard data")
                    miner_info = {
                        'address': addr,
                        'container_name': miner.get('container_name'),
                        'status': 'Offline',
                        'last_ping': 'Never',
                        'last_active': None
                    }
                    miner_data.append(miner_info)
                    continue

                last_ts = int(matched.get("last_active"))
                delta = now - last_ts
                readable = self._format_timedelta(delta)
                
                # Record activity with the new tracker
                self.uptime_tracker.record_activity(addr, last_ts)
                self.ping_logger.log_ping(addr, last_ts, 'online')
                
                miner_info = {
                    'address': addr,
                    'container_name': miner.get('container_name'),
                    'status': 'Online',
                    'last_ping': readable,
                    'last_active': last_ts
                }
                miner_data.append(miner_info)

                # Check if restart is needed
                last_restart = self.uptime_tracker.data[addr].get('last_restart', 0)
                in_cooldown = (now - last_restart) < COOLDOWN_PERIOD
                timeout_seconds = self.miner_timeouts.get(addr, DEFAULT_TIMEOUT * 60)
                
                if delta >= timeout_seconds and not in_cooldown:
                    self.restart_miner(miner)
                    self.uptime_tracker.record_restart(addr, now)
                    logging.info(f"Restarted miner {addr} due to timeout")
            
            return miner_data
        except Exception as e:
            logging.error(f"Error in refresh_data: {e}")
            return None

    def restart_miner(self, miner, manual=False):
        addr = miner['address']
        container = miner.get('container_name')
        is_docker = container is not None

        try:
            if is_docker:
                logging.info(f"Restarting Docker container {container} for miner {addr}")
                subprocess.run(["docker", "restart", container], check=True)
            else:
                logging.info(f"Restarting non-Docker miner {addr}")
                subprocess.run(["bash", NON_DOCKER_SCRIPT], check=True)
            
            alert_msg = f"Cortensor Monitor v{__version__}: Miner {addr} was restarted (Docker: {is_docker}){' (Manual)' if manual else ''}"
            self.notifier.send(alert_msg)
            return True
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to restart {addr}: {e}")
            error_msg = f"Cortensor Monitor v{__version__}: Failed to restart miner {addr}: {str(e)}{' (Manual)' if manual else ''}"
            self.notifier.send(error_msg)
            return False
        except Exception as e:
            logging.error(f"Unexpected error restarting {addr}: {e}")
            error_msg = f"Cortensor Monitor v{__version__}: Unexpected error restarting miner {addr}: {str(e)}{' (Manual)' if manual else ''}"
            self.notifier.send(error_msg)
            return False

    def check_for_updates(self):
        """Check for updates with rate limiting"""
        now = time.time()
        if now - self.last_update_check < self.update_check_interval:
            return
            
        self.last_update_check = now
        try:
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Cortensor-Monitor'
            }
            response = requests.get(GITHUB_REPO, headers=headers, timeout=10)
            
            # Handle rate limits
            if response.status_code == 403 and 'rate limit exceeded' in response.text.lower():
                reset_time = int(response.headers.get('X-RateLimit-Reset', now + 3600))
                self.update_check_interval = max(3600, reset_time - now)
                logging.warning(f"GitHub rate limit hit. Next check in {self.update_check_interval//3600} hours")
                return
                
            response.raise_for_status()
            latest_release = response.json()
            latest_version = latest_release['tag_name'].lstrip('v')
            
            if version.parse(latest_version) > version.parse(__version__):
                self.handle_update_available(latest_version, latest_release)
        except Exception as e:
            logging.error(f"Update check failed: {str(e)}")

    def handle_update_available(self, new_version, release_data):
        logging.info(f"Update available: v{new_version} (current: v{__version__})")
        logging.info(f"Release notes:\n{release_data.get('body', 'No release notes')}")
        
        alert_msg = (
            f"Cortensor Monitor Update Available!\n"
            f"Current: v{__version__}\n"
            f"New: v{new_version}\n"
            f"Download: {release_data['html_url']}"
        )
        self.notifier.send(alert_msg, skip_duplicate_check=True)

    def convert_time(self, seconds):
        """Backward compatibility method"""
        return self._format_timedelta(seconds)

def create_non_docker_script():
    script = """#!/bin/bash
sudo systemctl stop cortensor
sleep 20
if pgrep cortensord > /dev/null; then
  sudo systemctl stop cortensor
  pkill -9 cortensord
fi
if ! pgrep cortensord > /dev/null; then
  sudo systemctl start cortensor
fi
"""
    with open(NON_DOCKER_SCRIPT, 'w') as f:
        f.write(script)
    os.chmod(NON_DOCKER_SCRIPT, 0o755)

def initialize_monitor(docker=False, docker_compose_path=None, address=None):
    miners = []
    
    if docker:
        possible_paths = [
            docker_compose_path,
            "/home/deploy/cortensor-installer/docker-compose.yml",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml")
        ]
        
        docker_compose_path = None
        for path in possible_paths:
            if path and os.path.exists(path):
                docker_compose_path = path
                break
        
        if not docker_compose_path:
            logging.error("docker-compose.yml not found in default locations")
            while True:
                try:
                    user_path = input("Please enter full path to docker-compose.yml (or 'q' to quit): ").strip()
                    if user_path.lower() == 'q':
                        return False
                    if os.path.exists(user_path):
                        docker_compose_path = user_path
                        break
                    logging.error("File not found. Please try again.")
                except KeyboardInterrupt:
                    logging.info("Initialization cancelled by user")
                    return False
        
        try:
            with open(docker_compose_path, 'r') as f:
                lines = f.readlines()
            
            current_container = None
            for line in lines:
                line = line.strip()
                if line.startswith("container_name"):
                    current_container = line.split(":")[-1].strip()
                if "PUBLIC_KEY" in line:
                    addr = line.split('"')[1]
                    miners.append({"address": addr, "container_name": current_container})
                    
            if not miners:
                logging.error("No miners found in docker-compose.yml")
                return False
                
        except Exception as e:
            logging.error(f"Failed to parse docker-compose.yml: {e}")
            return False
    else:
        if not address:
            try:
                address = input("Enter the miner address: ").strip()
                if not address:
                    logging.error("No address provided")
                    return False
            except KeyboardInterrupt:
                logging.info("Initialization cancelled by user")
                return False
                
        miners.append({"address": address})
        create_non_docker_script()
        
        monitor = MinerMonitor()
        if not monitor.check_sudoers_permission():
            logging.info("Setting up sudoers permissions...")
            if not monitor.update_sudoers():
                return False
    
    try:
        with open(ADDRESS_FILE, 'w') as f:
            json.dump(miners, f, indent=2)
        logging.info(f"Initialized monitor with {len(miners)} miners")
        return True
    except Exception as e:
        logging.error(f"Failed to save miner configuration: {e}")
        return False

def configure_telegram(bot_token=None, chat_id=None, enable=True):
    settings = {
        "telegram_enabled": enable,
        "bot_token": bot_token if bot_token else "",
        "chat_id": chat_id if chat_id else ""
    }
    
    try:
        with open(ALERT_SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
        
        notifier = TelegramNotifier(ALERT_SETTINGS_FILE, SENT_ALERTS_FILE)
        if enable and bot_token and chat_id:
            return notifier.test()
        return True
    except Exception as e:
        logging.error(f"Failed to configure Telegram: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Cortensor Monitor - Headless Version")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize the monitor')
    init_group = init_parser.add_mutually_exclusive_group(required=True)
    init_group.add_argument('--docker', action='store_true', help='Use Docker miners')
    init_group.add_argument('--address', help='Miner address (for non-Docker setup)')
    init_parser.add_argument('--docker-compose', help='Path to docker-compose.yml (optional for Docker setup)')
    
    # Configure command
    config_parser = subparsers.add_parser('config', help='Configure monitor settings')
    config_parser.add_argument('--telegram-token', help='Telegram bot token')
    config_parser.add_argument('--telegram-chat', help='Telegram chat ID')
    config_parser.add_argument('--disable-telegram', action='store_true', help='Disable Telegram alerts')
    config_parser.add_argument('--check-interval', type=int, help='Check interval in seconds (default: 30)')
    config_parser.add_argument('--display-interval', type=int, help='Status display interval in seconds (default: 30)')
    config_parser.add_argument('--set-timeout', type=int, help='Set timeout threshold in minutes (use with --miner-address or alone for all miners)')
    config_parser.add_argument('--miner-address', help='Miner address to apply timeout to (optional with --set-timeout)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test monitor components')
    test_parser.add_argument('--telegram', action='store_true', help='Test Telegram alerts')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run the monitor')
    run_parser.add_argument('--quiet', action='store_true', help='Run without displaying status updates')
    
    # Control command
    control_parser = subparsers.add_parser('control', help='Control running monitor instance')
    control_group = control_parser.add_mutually_exclusive_group(required=True)
    control_group.add_argument('--restart-all', action='store_true', help='Restart all miners')
    control_group.add_argument('--restart', help='Restart specific miner by address')
    
    args = parser.parse_args()
    
    if args.command == 'init':
        if args.docker:
            success = initialize_monitor(docker=True, docker_compose_path=args.docker_compose)
        else:
            if not args.address:
                logging.error("You must specify an address for non-Docker setup")
                sys.exit(1)
            success = initialize_monitor(docker=False, address=args.address)
        
        if not success:
            sys.exit(1)
        logging.info("Initialization complete")
    
    elif args.command == 'config':
        if args.telegram_token or args.telegram_chat or args.disable_telegram:
            try:
                with open(ALERT_SETTINGS_FILE, 'r') as f:
                    settings = json.load(f)
            except FileNotFoundError:
                settings = {"telegram_enabled": False}
            
            if args.telegram_token:
                settings['bot_token'] = args.telegram_token
            if args.telegram_chat:
                settings['chat_id'] = args.telegram_chat
            if args.disable_telegram:
                settings['telegram_enabled'] = False
            elif args.telegram_token and args.telegram_chat:
                settings['telegram_enabled'] = True
            
            try:
                with open(ALERT_SETTINGS_FILE, 'w') as f:
                    json.dump(settings, f, indent=2)
                logging.info("Telegram settings updated")
            except Exception as e:
                logging.error(f"Failed to save Telegram settings: {e}")
                sys.exit(1)
            
            notifier = TelegramNotifier(ALERT_SETTINGS_FILE, SENT_ALERTS_FILE)
            if settings.get('telegram_enabled', False):
                if not notifier.test():
                    logging.warning("Telegram test failed with current settings")
        
        if args.check_interval:
            monitor = MinerMonitor()
            monitor.config['check_interval'] = args.check_interval
            monitor._save_config()
            logging.info(f"Check interval updated to {args.check_interval} seconds")
        
        if args.display_interval:
            monitor = MinerMonitor()
            monitor.display_interval = args.display_interval
            logging.info(f"Display interval updated to {args.display_interval} seconds")
        
        if args.set_timeout is not None:
            monitor = MinerMonitor()
            if monitor.set_miner_timeout(args.miner_address, args.set_timeout):
                if args.miner_address:
                    logging.info(f"Timeout for {args.miner_address} set to {args.set_timeout} minutes")
                else:
                    logging.info(f"Timeout for all miners set to {args.set_timeout} minutes")
            else:
                logging.error("Failed to set timeout")
                sys.exit(1)
    
    elif args.command == 'test':
        if args.telegram:
            notifier = TelegramNotifier(ALERT_SETTINGS_FILE, SENT_ALERTS_FILE)
            if not notifier.test():
                sys.exit(1)
    
    elif args.command == 'run':
        if not os.path.exists(ADDRESS_FILE):
            logging.error("Monitor not initialized. Please run 'init' first.")
            sys.exit(1)
        
        monitor = MinerMonitor()
        if args.quiet:
            monitor.display_interval = 0
        
        try:
            monitor.monitor_loop()
        except KeyboardInterrupt:
            logging.info("Monitor stopped by user")
        except Exception as e:
            logging.error(f"Monitor crashed: {e}")
            sys.exit(1)
    
    elif args.command == 'control':
        try:
            if args.restart_all:
                response = requests.post(
                    f'http://localhost:{CONTROL_SERVER_PORT}/restart',
                    json={'all': True},
                    timeout=5
                )
                if response.status_code == 200:
                    logging.info("Successfully initiated restart for all miners")
                else:
                    logging.error(f"Failed to restart all miners: {response.text}")
            elif args.restart:
                response = requests.post(
                    f'http://localhost:{CONTROL_SERVER_PORT}/restart',
                    json={'address': args.restart},
                    timeout=5
                )
                if response.status_code == 200:
                    logging.info(f"Successfully initiated restart for miner {args.restart}")
                elif response.status_code == 404:
                    logging.error(f"Miner not found: {args.restart}")
                else:
                    logging.error(f"Failed to restart miner {args.restart}: {response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to control server: {e}")
            sys.exit(1)

if __name__ == '__main__':
    main()