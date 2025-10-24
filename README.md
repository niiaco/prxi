# Ubuntu Proxy Server Setup

## Quick Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/niiaco/prxi.git && cd prxi && chmod +x install-proxy.sh && sudo ./install-proxy.sh```


PROXY_HOST: Listen host (default: 0.0.0.0)

PROXY_PORT: Listen port (default: 8089)

PROXY_WORKERS: Max worker threads (default: 100)

PROXY_TIMEOUT: Socket timeout (default: 15)

PROXY_BUFSIZE: Buffer size (default: 16384)

PROXY_AUTH: Basic auth "user:pass"

PROXY_UPSTREAM: Upstream proxy "host:port"

PROXY_LOG_LEVEL: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)


If you installed using the provided script, use the proxyctl command:

# Stop the service first
sudo proxyctl stop

# Disable the service from starting on boot
sudo proxyctl disable

# Check status to confirm it's stopped
sudo proxyctl status


If the management script isn't available, use these manual commands:

# Stop the service
sudo systemctl stop ubuntu-proxy

# Disable automatic start on boot
sudo systemctl disable ubuntu-proxy

# Remove the service file
sudo rm /etc/systemd/system/ubuntu-proxy.service

# Remove any override directories
sudo rm -rf /etc/systemd/system/ubuntu-proxy.service.d

# Reload systemd to recognize the changes
sudo systemctl daemon-reload

# Reset failed service count (if any)
sudo systemctl reset-failed
