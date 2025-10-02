import os, json, base64, hmac, hashlib, time, pathlib
from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs

# ===== Config (match your device.py) =====
DEVICE_ID      = "DT-042"
GROUP_ID       = b"ops-alpha"
PURPOSE        = b"vpn-psk"
EPOCH_LEN      = 60
AUTH_MAC_KEY   = b"server_auth_mac_key_64bytes________"   # demo only
COHORT_SECRET  = b"sealed_cohort_secret_32bytes_______"   # TPM/SE in prod

# ===== Paths =====
KEYS_DIR    = pathlib.Path("keys")
REG_DIR     = pathlib.Path("registry")
TICKETS_DIR = pathlib.Path("tickets")
STATE_DIR   = pathlib.Path("state")
STATE_FILE  = STATE_DIR / f"{DEVICE_ID}.json"

def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64u_dec(s: str) -> bytes: return base64.urlsafe_b64decode(s + "==")

# --- Kyber keys (same pattern as device.py) ---
def ensure_keys() -> Tuple[bytes, bytes]:
    priv_path = KEYS_DIR / f"{DEVICE_ID}.sk"
    pub_path  = KEYS_DIR / f"{DEVICE_ID}.pk"
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if priv_path.exists() and pub_path.exists():
        return pub_path.read_bytes(), priv_path.read_bytes()
    with oqs.KeyEncapsulation("Kyber1024") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    pub_path.write_bytes(pk)
    priv_path.write_bytes(sk)
    return pk, sk

def register_public_key(pk: bytes):
    REG_DIR.mkdir(parents=True, exist_ok=True)
    (REG_DIR / f"{DEVICE_ID}.pk").write_bytes(pk)

# --- Ticket verify + Kyber decap ---
def load_ticket_json():
    p = TICKETS_DIR / f"{DEVICE_ID}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None

def parse_ticket(ticket: dict) -> dict:
    payload_bytes = b64u_dec(ticket["payload_b64"])
    tag = b64u_dec(ticket["tag_b64"])
    expected = hmac.new(AUTH_MAC_KEY, payload_bytes, hashlib.sha512).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Invalid HMAC on ticket")
    p = json.loads(payload_bytes.decode())
    if p.get("aud") != DEVICE_ID:
        raise ValueError("Wrong audience")
    now = int(time.time())
    if not (p["epoch"] <= now < p["epoch"] + p["ttl_s"]):
        # You can relax this if you want to reseed from a slightly stale ticket.
        raise ValueError("Ticket outside acceptance window")
    # Minimal Kyber-1024 sanity
    ct = b64u_dec(p["ct_b64"])
    if len(ct) != 1568:
        raise ValueError(f"Unexpected ct length {len(ct)} (expect 1568 for Kyber-1024)")
    return p

def kyber_decap_ss(ct_b64: str, sk: bytes) -> bytes:
    ct = b64u_dec(ct_b64)
    try:
        kem = oqs.KeyEncapsulation("Kyber1024", secret_key=sk)
        ss = kem.decap_secret(ct)
    except TypeError:
        kem = oqs.KeyEncapsulation("Kyber1024")
        if hasattr(kem, "import_secret_key"):
            kem.import_secret_key(sk)
        ss = kem.decap_secret(ct) if hasattr(kem, "decap_secret") else kem.decapsulate(ct)
    finally:
        if hasattr(kem, "free"): kem.free()
    return ss  # 32 bytes

# --- Ratchet state (forward secrecy offline) ---
REQUIRED_KEYS = {"chain_b64", "counter", "last_epoch"}

def load_state():
    if not STATE_FILE.exists():
        return None
    try:
        s = json.loads(STATE_FILE.read_text())
        if not isinstance(s, dict) or not REQUIRED_KEYS.issubset(s.keys()):
            return None
        # quick sanity on types
        _ = b64u_dec(s["chain_b64"])
        _ = int(s["counter"])
        _ = int(s["last_epoch"])
        return s
    except Exception:
        return None

def save_state(state: dict):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))

def init_chain_from_bootstrap(ss: bytes, epoch: int) -> dict:
    # root_key = HKDF(ss || cohort_secret)
    ikm = ss + COHORT_SECRET
    root = HKDF(algorithm=hashes.SHA512(), length=32,
                salt=str(epoch).encode(), info=b"root:v1").derive(ikm)
    # chain_key = HMAC(root_key, "chain:v1")
    chain = hmac.new(root, b"chain:v1", hashlib.sha512).digest()
    return {"chain_b64": b64u(chain), "counter": 0, "last_epoch": epoch}

def next_minute_key(state: dict, purpose: bytes = PURPOSE) -> tuple[bytes, dict]:
    chain = b64u_dec(state["chain_b64"])
    ctr = int(state["counter"])
    key = hmac.new(chain, b"msg:" + purpose + b";ctr=" + str(ctr).encode(),
                   hashlib.sha512).digest()[:32]
    chain_next = hmac.new(chain, b"ratchet", hashlib.sha512).digest()
    state["chain_b64"] = b64u(chain_next)
    state["counter"] = ctr + 1
    return key, state

def reseed_chain_with_ss(state: dict, ss_new: bytes, epoch_new: int) -> dict:
    chain = b64u_dec(state["chain_b64"])
    mixed = HKDF(algorithm=hashes.SHA512(), length=32,
                 salt=None, info=(b"mix:epoch=" + str(epoch_new).encode())
                 ).derive(chain + ss_new)
    state["chain_b64"] = b64u(mixed)
    state["counter"] = 0
    state["last_epoch"] = epoch_new
    return state

def ensure_bootstrapped_state(sk: bytes) -> dict:
    """Return a valid state; wait for a ticket and bootstrap if needed."""
    s = load_state()
    if s is not None:
        return s
    print(f"[{DEVICE_ID}] no valid ratchet state; waiting for a ticket to bootstrap...")
    while True:
        ticket = load_ticket_json()
        if ticket:
            try:
                p = parse_ticket(ticket)
                ss = kyber_decap_ss(p["ct_b64"], sk)
                s = init_chain_from_bootstrap(ss, p["epoch"])
                save_state(s)
                print(f"[{DEVICE_ID}] bootstrapped; counter=0, epoch={p['epoch']}")
                return s
            except Exception as e:
                print(f"[{DEVICE_ID}] ticket present but unusable: {e}")
        time.sleep(2)

# --- Main loop ---
if __name__ == "__main__":
    print(f"[{DEVICE_ID}] ratchet loop starting (60s rotation, offline-capable)")
    pk, sk = ensure_keys()
    register_public_key(pk)

    state = ensure_bootstrapped_state(sk)

    while True:
        # Try reseed if a fresher ticket appears
        ticket = load_ticket_json()
        if ticket:
            try:
                p = parse_ticket(ticket)
                if p["epoch"] > int(state.get("last_epoch", 0)):
                    ss_new = kyber_decap_ss(p["ct_b64"], sk)
                    state = reseed_chain_with_ss(state, ss_new, p["epoch"])
                    save_state(state)
                    print(f"[{DEVICE_ID}] reseeded from epoch {p['epoch']}")
            except Exception:
                pass  # ignore stale/invalid tickets; continue offline

        key, state = next_minute_key(state, PURPOSE)
        save_state(state)
        print(f"[{DEVICE_ID}] {time.ctime()} key[{state['counter']-1}]: {key.hex()}")
        time.sleep(EPOCH_LEN)