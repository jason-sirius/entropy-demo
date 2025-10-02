import os, time, json, base64, hmac, hashlib, pathlib, glob
from typing import Dict
import oqs

# ===== Server constants (DEMO) =====
AUTH_MAC_KEY = b"server_auth_mac_key_64bytes________"   # for payload auth (demo)
REG_DIR      = pathlib.Path("registry")
TICKETS_DIR  = pathlib.Path("tickets")
LOGS_DIR     = pathlib.Path("logs")
EPOCH_LEN    = 60
TTL_S        = 120
ALG          = "Kyber1024"
MAC_ALG      = "HMAC-SHA512"
KID          = "auth-2025Q4"

prev_hash = b"\x00" * 32  # audit hash-chain head

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def now_epoch() -> int:
    return int(time.time() // EPOCH_LEN * EPOCH_LEN)

def load_registry() -> Dict[str, bytes]:
    """Load all device public keys from registry/*.pk"""
    REG_DIR.mkdir(parents=True, exist_ok=True)
    reg = {}
    for path in glob.glob(str(REG_DIR / "*.pk")):
        dev_id = pathlib.Path(path).stem  # filename without .pk
        reg[dev_id] = pathlib.Path(path).read_bytes()
    return reg

def new_ticket_for_device(device_id: str, pk: bytes) -> dict:
    """Encapsulate a per-device Kyber shared secret and build an authenticated ticket."""
    global prev_hash
    epoch = now_epoch()
    server_now = int(time.time())

    # Kyber encapsulation -> per-device ct + ss
    with oqs.KeyEncapsulation(ALG) as kem:
        ct, ss = kem.encap_secret(pk)

    # Ticket payload (server knows ss; cannot derive final because it lacks cohort_secret)
    payload = {
        "ver": 1,
        "alg": ALG,
        "mac_alg": MAC_ALG,
        "kid": KID,
        "aud": device_id,               # audience binding to this device
        "epoch": epoch,
        "ttl_s": TTL_S,
        "server_now": server_now,
        "ct_b64": b64u(ct),
        "chain": b64u(prev_hash)
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()

    # HMAC authenticate payload (demo). In prod, consider PQ signatures (Dilithium) instead.
    tag = hmac.new(AUTH_MAC_KEY, payload_bytes, hashlib.sha512).digest()

    # Update audit chain
    prev_hash = hashlib.sha256(payload_bytes).digest()

    return {
        "payload_b64": b64u(payload_bytes),
        "tag_b64": b64u(tag)
    }

if __name__ == "__main__":
    TICKETS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    reg = load_registry()
    if not reg:
        print("[server] No device public keys found in ./registry")
        print("Run the device once to generate and register a PK, then rerun the server.")
        raise SystemExit(1)

    for device_id, pk in reg.items():
        ticket = new_ticket_for_device(device_id, pk)
        out_path = TICKETS_DIR / f"{device_id}.json"
        out_path.write_text(json.dumps(ticket))
        print(f"[server] Wrote ticket for {device_id} -> {out_path}")
