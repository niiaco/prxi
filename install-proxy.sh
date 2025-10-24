#!/bin/bash
# install-proxy.sh - Installation script for Ubuntu Proxy Server

set -e

PROXY_USER="proxyuser"
SERVICE_NAME="ubuntu-proxy"
INSTALL_DIR="/opt/ubuntu-proxy"
SCRIPT_NAME="ubuntupro.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root"
    exit 1
fi

# Create user if doesn't exist
if ! id "$PROXY_USER" &>/dev/null; then
    print_status "Creating user: $PROXY_USER"
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$PROXY_USER"
fi

# Create installation directory
print_status "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
chown "$PROXY_USER:$PROXY_USER" "$INSTALL_DIR"

# Copy script to installation directory
print_status "Installing proxy script"
cp "$SCRIPT_NAME" "$INSTALL_DIR/"
chown "$PROXY_USER:$PROXY_USER" "$INSTALL_DIR/$SCRIPT_NAME"
chmod +x "$INSTALL_DIR/$SCRIPT_NAME"

# Create configuration directory
CONFIG_DIR="/etc/ubuntu-proxy"
mkdir -p "$CONFIG_DIR"
chown "$PROXY_USER:$PROXY_USER" "$CONFIG_DIR"

# Create systemd service file
print_status "Creating systemd service"
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Ubuntu Proxy Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=$PROXY_USER
Group=$PROXY_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/$SCRIPT_NAME
Restart=always
RestartSec=5
TimeoutStopSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

# Create configuration script
cat > "/usr/local/bin/configure-proxy" << 'EOF'
#!/bin/bash
CONFIG_DIR="/etc/ubuntu-proxy"

echo "Ubuntu Proxy Server Configuration"
echo "=================================="
echo

read -p "Enable Basic Authentication? (y/n): " enable_auth
if [[ $enable_auth == "y" ]]; then
    read -p "Username: " username
    read -s -p "Password: " password
    echo
    AUTH_CONFIG="$username:$password"
fi

read -p "Use upstream proxy? (y/n): " enable_upstream
if [[ $enable_upstream == "y" ]]; then
    read -p "Upstream proxy (host:port): " upstream
    UPSTREAM_CONFIG="$upstream"
fi

read -p "Listen port (default: 8089): " port
PORT=${port:-8089}

# Create service override directory
mkdir -p /etc/systemd/system/ubuntu-proxy.service.d

# Create override file
cat > /etc/systemd/system/ubuntu-proxy.service.d/override.conf << EOL
[Service]
Environment=PROXY_PORT=$PORT
EOL

if [[ ! -z "$AUTH_CONFIG" ]]; then
    echo "Environment=PROXY_AUTH=$AUTH_CONFIG" >> /etc/systemd/system/ubuntu-proxy.service.d/override.conf
fi

if [[ ! -z "$UPSTREAM_CONFIG" ]]; then
    echo "Environment=PROXY_UPSTREAM=$UPSTREAM_CONFIG" >> /etc/systemd/system/ubuntu-proxy.service.d/override.conf
fi

systemctl daemon-reload
echo "Configuration updated. Restart the service to apply changes."
EOF

chmod +x "/usr/local/bin/configure-proxy"

# Create management script
cat > "/usr/local/bin/proxyctl" << 'EOF'
#!/bin/bash
SERVICE_NAME="ubuntu-proxy"

case "$1" in
    start)
        systemctl start "$SERVICE_NAME"
        ;;
    stop)
        systemctl stop "$SERVICE_NAME"
        ;;
    restart)
        systemctl restart "$SERVICE_NAME"
        ;;
    status)
        systemctl status "$SERVICE_NAME"
        ;;
    enable)
        systemctl enable "$SERVICE_NAME"
        ;;
    disable)
        systemctl disable "$SERVICE_NAME"
        ;;
    logs)
        journalctl -u "$SERVICE_NAME" -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|enable|disable|logs}"
        exit 1
        ;;
esac
EOF

chmod +x "/usr/local/bin/proxyctl"

# Reload systemd and enable service
print_status "Reloading systemd and starting service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

print_status "Installation completed successfully!"
echo
echo "Service name: $SERVICE_NAME"
echo "Installation directory: $INSTALL_DIR"
echo "Configuration tool: configure-proxy"
echo "Management tool: proxyctl"
echo
echo "Quick start:"
echo "  sudo proxyctl status    # Check status"
echo "  sudo proxyctl logs      # View logs"
echo "  sudo configure-proxy    # Configure settings"