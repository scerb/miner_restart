# miner_restart
cortensor auto miner configurable restart for linux


1. Initialization Commands

python monitor.py init --docker [--docker-compose PATH]
Initializes monitor for Docker miners

Automatically detects miners from docker-compose.yml

--docker-compose: Optional path to docker-compose file if not in default location

python monitor.py init --address MINER_ADDRESS
Initializes monitor for a single non-Docker miner

Requires manual miner address input


2. Configuration Commands

python monitor.py config --telegram-token BOT_TOKEN --telegram-chat CHAT_ID
Configures Telegram alerts

Requires bot token and chat ID from Telegram BotFather

python monitor.py config --disable-telegram
Disables Telegram notifications

python monitor.py config --check-interval SECONDS
Sets how often (in seconds) the monitor checks miner status

Default: 30 seconds

python monitor.py config --display-interval SECONDS
Sets how often (in seconds) the status is displayed in console

Default: 30 seconds

python monitor.py config --set-timeout MINUTES [--miner-address ADDRESS]
Sets timeout threshold before restart (in minutes)

Without --miner-address: Applies to all miners

With --miner-address: Applies to specific miner only

Minimum: 6 minutes


3. Test Commands

python monitor.py test --telegram
Sends a test Telegram notification

Verifies alert system is working


4. Runtime Commands
python monitor.py run [--quiet]
Starts the monitoring service

--quiet: Runs without console output (logs only to file)


5. Control Commands (for running instances)
python monitor.py control --restart-all
Manually restarts all monitored miners

python monitor.py control --restart MINER_ADDRESS
Restarts a specific miner by address


6. HTTP API Commands (when monitor is running)
curl -X POST http://localhost:5000/restart -H 'Content-Type: application/json' -d '{"all":true}'
HTTP equivalent of control --restart-all

curl -X POST http://localhost:5000/restart -H 'Content-Type: application/json' -d '{"address":"MINER_ADDRESS"}'
HTTP equivalent of control --restart ADDRESS


Key Features:
Automatic Monitoring:

Checks miner status every 30 seconds (configurable), *No need to change this lower!!

Auto-restarts miners after timeout period

6-minute cooldown between restarts


Status Display:

Address         Container         Status    Last Ping    Uptime     Timeout
0xf652...       miner1_container  Online    2m 30s       36h 15m    12m
Last Ping: Minutes and seconds since last ping

Uptime: Hours and minutes since first ping/last restart

Timeout: Minutes remaining before auto-restart


Alerting:

Telegram notifications for:

Miner restarts

Restart failures

New version availability


Update Checks:

Automatic GitHub version checks every 24 hours


Logging:

Detailed logs in monitor.log

Ping history in ping_log.jsonl

Uptime data in uptime.json


File Locations:
Configuration: config.json

Miner addresses: addresses.json

Alert settings: alert_settings.json

Logs: monitor.log


Typical Workflow:
Initialize: python monitor.py init --docker

Configure alerts: python monitor.py config --telegram-token XXX --telegram-chat YYY

Run: python monitor.py run


(Optional) Manual restart: python monitor.py control --restart 0xf652...

The system is designed to run continuously in the background, automatically handling miner monitoring and restarts while providing multiple control options.

