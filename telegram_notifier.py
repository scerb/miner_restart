import os
import json
import logging
import requests
from typing import Set, Optional

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
            return False

        bot_token = self.settings.get("bot_token", "").strip()
        chat_id = self.settings.get("chat_id", "").strip()

        if not (bot_token and chat_id):
            logging.warning("Telegram bot token or chat ID missing.")
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
            else:
                logging.error(f"Telegram API error {response.status_code}: {response.text}")
                return False
        except Exception as e:
            logging.error(f"Failed to send Telegram alert: {e}")
            return False

    def test(self) -> bool:
        return self.send("Test alert from Cortensor Monitor", skip_duplicate_check=True)