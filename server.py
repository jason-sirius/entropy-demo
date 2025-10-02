# server.py
import os, time, hmac, hashlib, json, base64

AUTH_MAC_KEY = b"server_auth_mac_key_64bytes________"
prev_hash = b"\x00" * 32
EPOCH_LEN = 60

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def now_epoch(): return int(time.time() // EPOCH_LEN * EPOCH_LEN)

def new_entropy_ticket():
    global prev_hash
    epoch = now_epoch()
    seed_epoch = os.urandom(32)

    payload = {
        "ver": 1,
        "epoch": epoch,
        "ttl_s": 120,
        "seed_b64": b64u(seed_epoch),
        "chain": b64u(prev_hash),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
    tag = hmac.new(AUTH_MAC_KEY, payload_bytes, hashlib.sha512).digest()
    prev_hash = hashlib.sha256(payload_bytes).digest()

    return {"payload_b64": b64u(payload_bytes), "tag_b64": b64u(tag)}

if __name__ == "__main__":
    print(new_entropy_ticket())
