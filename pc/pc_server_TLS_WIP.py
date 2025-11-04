import socket, ctypes, threading, ssl, os, sys

HOST = "localhost"
PORT = 55005
MOUSEEVENTF_WHEEL = 0x0800

CERTFILE = "server.crt"     # server certificate (PEM)
KEYFILE = "server.key"      # server private key (PEM)
DHPARAM = "dhparam.pem"     # Diffie-Hellman parameters (PEM)

def send_wheel(delta):
    # Windows expects wheel delta in "WHEEL_DELTA" units (120 per notch)
    ctypes.windll.user32.mouse_event(MOUSEEVENTF_WHEEL, 0, 0, int(delta), 0)

def handle_client(conn, addr):
    print(f"[DEBUG] New connection from {addr}")
    try:
        try:
            conn.sendall(b"OK\n")
            print("[DEBUG] Sent OK to client")
        except Exception as e:
            print(f"[DEBUG] Failed to send OK: {e}")

        while True:
            chunk = conn.recv(1024)
            if not chunk:
                print("[DEBUG] Connection closed by client")
                break
            print(f"[DEBUG] Received chunk ({len(chunk)} bytes)")
            for line in chunk.decode(errors='ignore').splitlines():
                print(f"[DEBUG] Command line: {line!r}")
                if line.startswith("SCROLL:"):
                    try:
                        d = int(line.split(":",1)[1])
                        print(f"[DEBUG] Scrolling by {d}")
                        send_wheel(d)
                    except Exception as e:
                        print(f"[DEBUG] Error handling SCROLL: {e}")
                elif line.strip() == "DISCONNECT":
                    print("[DEBUG] DISCONNECT received; closing connection")
                    conn.close()
                    return
                else:
                    print(f"[DEBUG] Unknown command: {line!r}")
    except Exception as e:
        print(f"[DEBUG] Exception in handle_client: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[DEBUG] Connection {addr} cleaned up")

def make_ssl_context():
    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        print("[ERROR] Certificate or key file not found. Generate them first.")
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # disable old protocols
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    # prefer server ciphers
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    # load cert/key
    ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    # load DH params if provided
    if os.path.exists(DHPARAM):
        try:
            ctx.load_dh_params(DHPARAM)
            print("[DEBUG] Loaded DH params from", DHPARAM)
        except Exception as e:
            print("[WARNING] Failed to load DH params:", e)
    else:
        print("[WARNING] DH params file not found; ephemeral DH may not be available")
    # set secure ciphers (adjust as needed)
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
    except Exception as e:
        print("[WARNING] Failed to set ciphers:", e)
    return ctx

def main():
    ctx = make_ssl_context()

    try:
        print("[DEBUG] Determining real IP via UDP connect")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s2:
            s2.connect(('8.8.8.8', 80))
            real_ip = s2.getsockname()[0]
        print(f"[DEBUG] Real IP determined: {real_ip}")
    except Exception as e:
        print(f"[DEBUG] UDP method failed: {e}; falling back")
        try:
            real_ip = socket.gethostbyname(socket.gethostname())
            print(f"[DEBUG] Hostname IP: {real_ip}")
        except Exception as e2:
            print(f"[DEBUG] Hostname lookup failed: {e2}; using {HOST}")
            real_ip = HOST

    print("PC TLS Server Starting, ip:", real_ip)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print(f"[DEBUG] Binding to {(real_ip, PORT)}")
        s.bind((real_ip, PORT))
        s.listen()
        print("Listening on", PORT)
        print("[DEBUG] Accept loop started (TLS)")

        while True:
            try:
                conn, addr = s.accept()
                print("Client connected (raw):", addr)
                # wrap socket with TLS (per-connection)
                try:
                    ssl_conn = ctx.wrap_socket(conn, server_side=True)
                    print("[DEBUG] TLS handshake complete with", addr)
                except ssl.SSLError as e:
                    print(f"[ERROR] TLS handshake failed for {addr}: {e}")
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue

                # hand ssl_conn to handler in a thread
                t = threading.Thread(target=handle_client, args=(ssl_conn, addr), daemon=True)
                t.start()
            except Exception as e:
                print("[ERROR] Accept loop exception:", e)

if __name__ == "__main__":
    main()