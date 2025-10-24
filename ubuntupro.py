#!/usr/bin/env python3
"""
Robust HTTP/HTTPS forward proxy (no evasive techniques).

Features:
- Handles HTTP/1.0 and HTTP/1.1 requests (absolute-form and origin-form).
- Handles CONNECT for HTTPS with tunneling.
- ThreadPoolExecutor worker pool for controlled concurrency.
- Timeouts, retries, and safe socket options.
- Optional Basic Auth (simple header check).
- Optional upstream proxy chaining (for legitimate proxying).
- Simple logging to stdout.
- DNS resolution via socket.getaddrinfo.
- Environment variable configuration support.

Do NOT use for evading detection, unauthorized scraping, or bypassing restrictions.
"""

import socket
import threading
import sys
import traceback
import os
from concurrent.futures import ThreadPoolExecutor
from base64 import b64decode
from typing import Tuple, Optional

# Configuration with environment variable support
LISTEN_HOST = os.getenv('PROXY_HOST', '0.0.0.0')
LISTEN_PORT = int(os.getenv('PROXY_PORT', '8089'))
MAX_WORKERS = int(os.getenv('PROXY_WORKERS', '100'))
SOCKET_TIMEOUT = int(os.getenv('PROXY_TIMEOUT', '15'))
RECV_BUFSIZE = int(os.getenv('PROXY_BUFSIZE', '16384'))  # 16KB

# Basic Auth from environment
auth_env = os.getenv('PROXY_AUTH')
if auth_env:
    try:
        BASIC_AUTH_USER, BASIC_AUTH_PASS = auth_env.split(':', 1)
    except:
        BASIC_AUTH_USER = None
        BASIC_AUTH_PASS = None
else:
    BASIC_AUTH_USER = None
    BASIC_AUTH_PASS = None

# Upstream proxy from environment
upstream_env = os.getenv('PROXY_UPSTREAM')
if upstream_env:
    try:
        h, p = upstream_env.split(':', 1)
        UPSTREAM_PROXY = (h, int(p))
    except:
        UPSTREAM_PROXY = None
else:
    UPSTREAM_PROXY = None

# Log level from environment
LOG_LEVEL = os.getenv('PROXY_LOG_LEVEL', 'INFO').upper()

# Simple logger with levels
def log(msg: str, level: str = "INFO"):
    level_colors = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m"  # Magenta
    }
    reset_color = "\033[0m"
    
    level_num = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    config_level_num = level_num.get(LOG_LEVEL, 1)
    msg_level_num = level_num.get(level, 1)
    
    if msg_level_num >= config_level_num:
        color = level_colors.get(level, "")
        print(f"{color}[{level}]{reset_color} {msg}", flush=True)

def parse_request_line(data: bytes) -> Tuple[Optional[str], Optional[int], bytes]:
    """
    Parses initial request bytes and returns (host, port, remaining_bytes)
    For CONNECT it extracts host:port from request line.
    For normal HTTP it tries to read Host header.
    """
    try:
        s = data.decode('utf-8', errors='ignore')
        lines = s.split('\r\n')
        if not lines:
            return None, None, data

        first = lines[0].split()
        if len(first) < 2:
            return None, None, data

        method = first[0].upper()
        target = first[1]

        # CONNECT host:port
        if method == 'CONNECT':
            host_port = target.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            log(f"CONNECT request for {host}:{port}", "DEBUG")
            return host, port, data

        # For regular HTTP requests, prefer Host: header
        host = None
        port = None
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                host_part = line.split(':', 1)[1].strip()
                if ':' in host_part:
                    h, p = host_part.split(':', 1)
                    host, port = h.strip(), int(p.strip())
                else:
                    host = host_part.strip()
                    port = 80
                break

        # If no Host header, but target is absolute URI (http://host/...)
        if not host and target.startswith('http://'):
            try:
                without_proto = target.split('://', 1)[1]
                host_part = without_proto.split('/', 1)[0]
                if ':' in host_part:
                    h, p = host_part.split(':', 1)
                    host, port = h, int(p)
                else:
                    host, port = host_part, 80
            except Exception as e:
                log(f"Error parsing absolute URI: {e}", "DEBUG")
                pass

        # Also try https:// for completeness
        if not host and target.startswith('https://'):
            try:
                without_proto = target.split('://', 1)[1]
                host_part = without_proto.split('/', 1)[0]
                if ':' in host_part:
                    h, p = host_part.split(':', 1)
                    host, port = h, int(p)
                else:
                    host, port = host_part, 443
            except Exception as e:
                log(f"Error parsing HTTPS absolute URI: {e}", "DEBUG")
                pass

        if host and port:
            log(f"HTTP request for {host}:{port}, method: {method}", "DEBUG")
        else:
            log(f"Could not determine host/port from request", "WARNING")

        return host, port, data
    except Exception as e:
        log(f"Error parsing request line: {e}", "ERROR")
        return None, None, data

def resolve_host(host: str, port: int) -> Tuple[str, int]:
    """
    Resolves host to an IP address using system resolver.
    Returns (ip, port). If resolution fails, raises.
    """
    try:
        log(f"Resolving {host}:{port}", "DEBUG")
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        # Prefer IPv4 first (but keep system order)
        for family, socktype, proto, canonname, sockaddr in infos:
            ip, resolved_port = sockaddr[0], sockaddr[1]
            log(f"Resolved {host} -> {ip}", "DEBUG")
            return ip, resolved_port
        raise RuntimeError(f"DNS resolution failed for {host}")
    except Exception as e:
        log(f"DNS resolution error for {host}:{port}: {e}", "ERROR")
        raise

class ProxyServer:
    def __init__(self, host=LISTEN_HOST, port=LISTEN_PORT, max_workers=MAX_WORKERS):
        self.host = host
        self.port = port
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.shutdown_event = threading.Event()
        self.active_connections = 0
        self.connection_lock = threading.Lock()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Set socket timeout for accept calls
            listen_sock.settimeout(1)
            listen_sock.bind((self.host, self.port))
            listen_sock.listen(256)
            log(f"Proxy listening on {self.host}:{self.port}", "INFO")
            if BASIC_AUTH_USER:
                log("Basic authentication enabled", "INFO")
            if UPSTREAM_PROXY:
                log(f"Upstream proxy configured: {UPSTREAM_PROXY[0]}:{UPSTREAM_PROXY[1]}", "INFO")

            try:
                while not self.shutdown_event.is_set():
                    try:
                        client_sock, client_addr = listen_sock.accept()
                        client_sock.settimeout(SOCKET_TIMEOUT)
                        with self.connection_lock:
                            self.active_connections += 1
                        log(f"Accepted connection from {client_addr} (active: {self.active_connections})", "DEBUG")
                        # Submit to thread pool
                        self.executor.submit(self.handle_client, client_sock, client_addr)
                    except socket.timeout:
                        # Timeout on accept, check for shutdown
                        continue
                    except KeyboardInterrupt:
                        log("Received interrupt signal, shutting down...", "INFO")
                        break
                    except Exception as e:
                        log(f"Accept loop error: {e}", "ERROR")
            finally:
                log("Shutting down thread pool...", "INFO")
                self.executor.shutdown(wait=True)
                log("Proxy server stopped", "INFO")

    def handle_client(self, client_sock: socket.socket, client_addr):
        try:
            # Read initial bytes (headers) without blocking forever
            initial = self.recv_all_headers(client_sock)
            if not initial:
                log(f"No data received from {client_addr}", "DEBUG")
                client_sock.close()
                return

            # Basic auth check (if enabled)
            if BASIC_AUTH_USER and BASIC_AUTH_PASS:
                if not self.check_basic_auth(initial):
                    log(f"Authentication failed for {client_addr}", "WARNING")
                    self.send_407(client_sock)
                    client_sock.close()
                    return
                else:
                    log(f"Authentication successful for {client_addr}", "DEBUG")

            host, port, remaining_data = parse_request_line(initial)
            if not host or not port:
                log(f"Could not parse target from client {client_addr}", "WARNING")
                self.send_400(client_sock)
                client_sock.close()
                return

            # Decide whether CONNECT tunnel or plain HTTP
            if initial.startswith(b'CONNECT'):
                self.handle_connect(client_sock, client_addr, initial, host, port)
            else:
                self.handle_http_request(client_sock, client_addr, initial, host, port)
        except Exception as e:
            log(f"Client handler error {client_addr}: {e}", "ERROR")
            if LOG_LEVEL == "DEBUG":
                log(traceback.format_exc(), "DEBUG")
            try:
                client_sock.close()
            except:
                pass
        finally:
            with self.connection_lock:
                self.active_connections -= 1
            log(f"Connection closed from {client_addr} (active: {self.active_connections})", "DEBUG")

    def recv_all_headers(self, sock: socket.socket, max_header_bytes=65536) -> bytes:
        """
        Read until CRLF CRLF (end of headers) or timeout.
        Returns bytes (may include beginning of body).
        """
        data = b''
        try:
            while b'\r\n\r\n' not in data and len(data) < max_header_bytes:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # small optimization: if it's a CONNECT, headers end quickly
                if data.startswith(b'CONNECT') and b'\r\n\r\n' in data:
                    break
        except socket.timeout:
            log("Timeout while reading headers", "DEBUG")
        except Exception as e:
            log(f"Error reading headers: {e}", "DEBUG")
        return data

    def check_basic_auth(self, initial: bytes) -> bool:
        """
        Very simple Basic Auth check: look for Authorization header.
        """
        try:
            s = initial.decode('utf-8', errors='ignore')
            for line in s.split('\r\n'):
                if line.lower().startswith('proxy-authorization:'):
                    val = line.split(':', 1)[1].strip()
                    if val.lower().startswith('basic '):
                        try:
                            payload = b64decode(val.split()[1]).decode('utf-8')
                            user, passwd = payload.split(':', 1)
                            return user == BASIC_AUTH_USER and passwd == BASIC_AUTH_PASS
                        except Exception as e:
                            log(f"Auth parsing error: {e}", "DEBUG")
                            return False
            return False
        except Exception as e:
            log(f"Auth check error: {e}", "ERROR")
            return False

    def send_407(self, client_sock: socket.socket):
        """Send Proxy Authentication Required response"""
        body = b'Proxy Authentication Required'
        resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n" \
               b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n" \
               b"Content-Length: " + str(len(body)).encode() + b"\r\n" \
               b"Connection: close\r\n\r\n" + body
        try:
            client_sock.sendall(resp)
        except Exception as e:
            log(f"Error sending 407: {e}", "DEBUG")

    def send_400(self, client_sock: socket.socket):
        """Send Bad Request response"""
        body = b'Bad Request - Could not parse target'
        resp = b"HTTP/1.1 400 Bad Request\r\n" \
               b"Content-Length: " + str(len(body)).encode() + b"\r\n" \
               b"Connection: close\r\n\r\n" + body
        try:
            client_sock.sendall(resp)
        except Exception as e:
            log(f"Error sending 400: {e}", "DEBUG")

    def handle_connect(self, client_sock: socket.socket, client_addr, initial: bytes, host: str, port: int):
        """
        Handle CONNECT method: establish TCP tunnel between client and target (or upstream proxy).
        """
        log(f"Tunnel request: {client_addr} -> {host}:{port}", "INFO")
        upstream = UPSTREAM_PROXY
        remote = None
        
        try:
            if upstream:
                # If upstream proxy is set, connect to it and send CONNECT to it
                upstream_host, upstream_port = upstream
                upstream_ip, upstream_port = resolve_host(upstream_host, upstream_port)
                remote = socket.create_connection((upstream_ip, upstream_port), timeout=SOCKET_TIMEOUT)
                remote.settimeout(SOCKET_TIMEOUT)
                # send CONNECT to upstream
                connect_cmd = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
                remote.sendall(connect_cmd.encode('utf-8'))
                # read upstream response headers
                resp = self.recv_all_headers(remote)
                # If upstream didn't return 200, relay error
                if not resp.startswith(b'HTTP/1.1 200') and not resp.startswith(b'HTTP/1.0 200'):
                    log(f"Upstream proxy rejected CONNECT: {resp[:100]}", "ERROR")
                    client_sock.sendall(resp or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    return
                log(f"Upstream tunnel established to {host}:{port}", "INFO")
            else:
                # Direct connect
                ip, resolved_port = resolve_host(host, port)
                remote = socket.create_connection((ip, resolved_port), timeout=SOCKET_TIMEOUT)
                remote.settimeout(SOCKET_TIMEOUT)
                log(f"Direct tunnel established to {host}:{port} ({ip})", "INFO")

            # Inform client that tunnel is established
            try:
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except Exception as e:
                log(f"Error sending 200 to client: {e}", "ERROR")
                return

            # Start bidirectional tunnel
            self.pipe_sockets(client_sock, remote)
            log(f"Tunnel closed: {client_addr} -> {host}:{port}", "INFO")

        except Exception as e:
            log(f"CONNECT error for {host}:{port}: {e}", "ERROR")
            try:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except:
                pass
        finally:
            # Ensure sockets are closed
            try:
                if remote:
                    remote.close()
            except:
                pass

    def handle_http_request(self, client_sock: socket.socket, client_addr, initial: bytes, host: str, port: int):
        """
        Handle non-CONNECT (regular HTTP) requests: forward to target, stream response back.
        """
        log(f"HTTP request: {client_addr} -> {host}:{port}", "INFO")
        upstream = UPSTREAM_PROXY
        remote = None
        
        try:
            if upstream:
                upstream_host, upstream_port = upstream
                upstream_ip, upstream_port = resolve_host(upstream_host, upstream_port)
                remote = socket.create_connection((upstream_ip, upstream_port), timeout=SOCKET_TIMEOUT)
                remote.settimeout(SOCKET_TIMEOUT)
                # When chaining to upstream, send the original headers as-is
                remote.sendall(initial)
                log(f"Forwarding HTTP request via upstream to {host}:{port}", "DEBUG")
            else:
                ip, resolved_port = resolve_host(host, port)
                remote = socket.create_connection((ip, resolved_port), timeout=SOCKET_TIMEOUT)
                remote.settimeout(SOCKET_TIMEOUT)
                # Convert absolute-form to origin-form for origin servers
                to_send = self.normalize_request_for_origin(initial, host)
                remote.sendall(to_send)
                log(f"Direct HTTP request to {host}:{port} ({ip})", "DEBUG")

            # Now forward response back to client
            self.pipe_sockets(remote, client_sock)
            log(f"HTTP request completed: {client_addr} -> {host}:{port}", "INFO")

        except Exception as e:
            log(f"HTTP forward error for {host}:{port}: {e}", "ERROR")
            try:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except:
                pass
        finally:
            try:
                if remote:
                    remote.close()
            except:
                pass

    def normalize_request_for_origin(self, data: bytes, host: str) -> bytes:
        """
        Convert an absolute-form request line (proxy-client) to origin-form (server) if needed.
        e.g. "GET http://example.com/path HTTP/1.1" -> "GET /path HTTP/1.1"
        """
        try:
            s = data.decode('utf-8', errors='ignore')
            lines = s.split('\r\n')
            if not lines:
                return data
            first = lines[0].split(' ', 2)
            if len(first) < 2:
                return data
            method = first[0]
            target = first[1]
            version = first[2] if len(first) > 2 else 'HTTP/1.1'
            
            if target.startswith('http://') or target.startswith('https://'):
                # strip scheme and host
                after = target.split('://', 1)[1]
                path_idx = after.find('/')
                if path_idx == -1:
                    path = '/'
                else:
                    path = after[path_idx:]
                # rebuild first line
                lines[0] = f"{method} {path} {version}"
                # Ensure Host header exists
                has_host = any(l.lower().startswith('host:') for l in lines[1:])
                if not has_host:
                    lines.insert(1, f"Host: {host}")
                return ("\r\n".join(lines)).encode('utf-8')
            else:
                return data
        except Exception as e:
            log(f"Error normalizing request: {e}", "DEBUG")
            return data

    def pipe_sockets(self, a: socket.socket, b: socket.socket):
        """
        Bidirectional pipe between socket a and b until both close.
        Uses two threads for simplicity.
        """
        def forward(src, dst, src_name, dst_name):
            try:
                while True:
                    data = src.recv(RECV_BUFSIZE)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception as e:
                log(f"Pipe error {src_name}->{dst_name}: {e}", "DEBUG")
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=forward, args=(a, b, "remote", "client"), daemon=True)
        t2 = threading.Thread(target=forward, args=(b, a, "client", "remote"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            a.close()
        except:
            pass
        try:
            b.close()
        except:
            pass

if __name__ == "__main__":
    # Quick CLI flags
    import argparse
    parser = argparse.ArgumentParser(description="Simple robust HTTP/HTTPS forward proxy")
    parser.add_argument('--host', default=LISTEN_HOST, help=f"Listen host (default: {LISTEN_HOST})")
    parser.add_argument('--port', default=LISTEN_PORT, type=int, help=f"Listen port (default: {LISTEN_PORT})")
    parser.add_argument('--workers', default=MAX_WORKERS, type=int, help=f"Max workers (default: {MAX_WORKERS})")
    parser.add_argument('--upstream', default=None, help="Upstream proxy host:port")
    parser.add_argument('--auth', default=None, help="Basic auth user:pass")
    parser.add_argument('--timeout', default=SOCKET_TIMEOUT, type=int, help=f"Socket timeout (default: {SOCKET_TIMEOUT})")
    parser.add_argument('--log-level', default=LOG_LEVEL, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                       help="Log level (default: INFO)")
    
    args = parser.parse_args()

    # Override from command line args
    if args.upstream:
        try:
            h, p = args.upstream.split(':', 1)
            UPSTREAM_PROXY = (h, int(p))
        except Exception as e:
            log(f"Invalid upstream format '{args.upstream}', should be host:port: {e}", "ERROR")
            sys.exit(1)

    if args.auth:
        try:
            u, pw = args.auth.split(':', 1)
            BASIC_AUTH_USER = u
            BASIC_AUTH_PASS = pw
        except Exception as e:
            log(f"Invalid auth format '{args.auth}', should be user:pass: {e}", "ERROR")
            sys.exit(1)

    # Set log level from command line
    LOG_LEVEL = args.log_level

    log(f"Starting Ubuntu Proxy Server v1.0", "INFO")
    log(f"Configuration: host={args.host}, port={args.port}, workers={args.workers}, timeout={args.timeout}, log_level={LOG_LEVEL}", "INFO")
    if BASIC_AUTH_USER:
        log("Basic authentication: ENABLED", "INFO")
    else:
        log("Basic authentication: DISABLED", "INFO")
    if UPSTREAM_PROXY:
        log(f"Upstream proxy: {UPSTREAM_PROXY[0]}:{UPSTREAM_PROXY[1]}", "INFO")
    else:
        log("Upstream proxy: DISABLED", "INFO")

    server = ProxyServer(host=args.host, port=args.port, max_workers=args.workers)
    try:
        server.start()
    except KeyboardInterrupt:
        log("Interrupted by user, exiting gracefully...", "INFO")
    except Exception as e:
        log(f"Fatal error: {e}", "CRITICAL")
        sys.exit(1)