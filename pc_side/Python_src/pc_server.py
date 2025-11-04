import socket, ctypes, threading

HOST = "localhost"
PORT = 55005
MOUSEEVENTF_WHEEL = 0x0800

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

def main():
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

    print("PC Server Starting, ip:", real_ip)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[DEBUG] Binding to {(real_ip, PORT)}")
        s.bind((real_ip, PORT))
        s.listen()
        print("Listening on", PORT)
        print("[DEBUG] Accept loop started")
        while True:
            conn, addr = s.accept()
            print("Client connected:", addr)
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    main()