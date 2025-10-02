import os, json, base64, hmac, hashlib, time, pathlib
from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs

# ===== Device constants (DEMO) =====
DEVICE_ID      = "DT-042"
GROUP_ID       = "ops-alpha"
DEFAULT_PURPOSE= b"vpn-psk"
COHORT_SECRET  = b"sealed_cohort_secret_32bytes_______"   # sealed in TPM/SE in prod
AUTH_MAC_KEY   = b"server_auth_mac_key_64bytes________"   # demo HMAC
KEYS_DIR       = pathlib.Path("keys")
REG_DIR        = pathlib.Path("registry")
TICKETS_DIR    = pathlib.Path("tickets")
STATE_DIR      = pathlib.Path("state")
STATE_FILE     = STATE_DIR / f"{DEVICE_ID}.json"

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")

def ensure_keys() -> Tuple[bytes, bytes]:
    """Create or load Kyber-1024 keypair for this device."""
    priv_path = KEYS_DIR / f"{DEVICE_ID}.sk"
    pub_path  = KEYS_DIR / f"{DEVICE_ID}.pk"
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if priv_path.exists() and pub_path.exists():
        sk = priv_path.read_bytes()
        pk = pub_path.read_bytes()
        return pk, sk
    with oqs.KeyEncapsulation("Kyber1024") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    pub_path.write_bytes(pk)
    priv_path.write_bytes(sk)
    return pk, sk

def register_public_key(pk: bytes):
    REG_DIR.mkdir(parents=True, exist_ok=True)
    (REG_DIR / f"{DEVICE_ID}.pk").write_bytes(pk)

def _kem_for_decapsulation(sk: bytes):
    try:
        return oqs.KeyEncapsulation("Kyber1024", secret_key=sk)  # modern API
    except TypeError:
        kem = oqs.KeyEncapsulation("Kyber1024")
        if hasattr(kem, "import_secret_key"):
            kem.import_secret_key(sk)
            return kem
        raise RuntimeError("Your oqs binding doesn’t support loading a secret key.")

def _kem_decap(kem, ct: bytes) -> bytes:
    if hasattr(kem, "decap_secret"):
        return kem.decap_secret(ct)
    if hasattr(kem, "decapsulate"):
        return kem.decapsulate(ct)
    raise RuntimeError("oqs KeyEncapsulation has no decapsulation method.")

# ---------- Bootstrap & tickets ----------

def load_ticket():
    p = TICKETS_DIR / f"{DEVICE_ID}.json"
    if not p.exists():
        raise FileNotFoundError(f"Ticket not found: {p}")
    return json.loads(p.read_text())

def verify_and_parse_ticket(ticket: dict) -> dict:
    payload_bytes = b64u_dec(ticket["payload_b64"])
    tag           = b64u_dec(ticket["tag_b64"])
    expected = hmac.new(AUTH_MAC_KEY, payload_bytes, hashlib.sha512).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Invalid HMAC on ticket payload.")
    p = json.loads(payload_bytes.decode())
    if p["aud"] != DEVICE_ID:
        raise ValueError(f"Wrong audience: expected {DEVICE_ID}, got {p['aud']}")
    now = int(time.time())
    if not (p["epoch"] <= now < p["epoch"] + p["ttl_s"]):
        raise ValueError("Ticket outside acceptance window.")
    return p

def recover_ss_from_ticket(parsed_payload: dict, sk: bytes) -> bytes:
    ct = b64u_dec(parsed_payload["ct_b64"])
    kem = _kem_for_decapsulation(sk)
    try:
        return _kem_decap(kem, ct)
    finally:
        if hasattr(kem, "free"):
            kem.free()

# ---------- Ratchet state ----------

def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return None

def save_state(state: dict):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))

def init_from_bootstrap(ss: bytes, epoch: int) -> dict:
    """
    Build the initial root_key and chain_key from bootstrap secrets.
    root_key   = HKDF(ss || cohort_secret)
    chain_key0 = HMAC(root_key, "chain:v1")
    """
    info = b"purpose=" + DEFAULT_PURPOSE + b";group=" + GROUP_ID.encode() + b";epoch=" + str(epoch).encode()
    ikm  = ss + COHORT_SECRET
    root = HKDF(algorithm=hashes.SHA512(), length=32, salt=str(epoch).encode(), info=info).derive(ikm)
    chain = hmac.new(root, b"chain:v1", hashlib.sha512).digest()
    return {
        "root_key_b64": b64u(root),
        "chain_key_b64": b64u(chain),
        "counter": 0,
        "last_epoch": epoch
    }

def derive_next_key(state: dict, purpose: bytes = DEFAULT_PURPOSE) -> Tuple[bytes, dict]:
    """
    Derive a fresh working key and advance the chain.
    msg_key = HMAC(chain_key, "msg:"||purpose||counter)
    chain'  = HMAC(chain_key, "ratchet")
    """
    chain = b64u_dec(state["chain_key_b64"])
    ctr   = state["counter"]
    msg_key = hmac.new(chain, b"msg:" + purpose + b";ctr=" + str(ctr).encode(), hashlib.sha512).digest()[:32]
    chain_next = hmac.new(chain, b"ratchet", hashlib.sha512).digest()
    state["chain_key_b64"] = b64u(chain_next)
    state["counter"] = ctr + 1
    return msg_key, state

def reseed_with_new_ticket(state: dict, ss_new: bytes, epoch_new: int) -> dict:
    """
    Mix fresh PQ entropy into the chain for PCS:
    chain' = HKDF(chain || ss_new, info="mix:epoch")
    counter resets to 0 for clarity (optional).
    """
    chain = b64u_dec(state["chain_key_b64"])
    info  = b"mix:epoch=" + str(epoch_new).encode()
    mixed = HKDF(algorithm=hashes.SHA512(), length=64, salt=None, info=info).derive(chain + ss_new)
    # Split: first half becomes new chain, second half could be new root if desired
    new_chain = mixed[:32]
    state["chain_key_b64"] = b64u(new_chain)
    state["counter"] = 0
    state["last_epoch"] = epoch_new
    return state

# ---------- Demo entrypoint ----------

if __name__ == "__main__":
    print(f"[{DEVICE_ID}] starting ratchet demo")
    pk, sk = ensure_keys()
    register_public_key(pk)

    # Load existing state or bootstrap from ticket
    state = load_state()
    if state is None:
        print(f"[{DEVICE_ID}] no state found; bootstrapping from ticket")
        ticket = load_ticket()
        p = verify_and_parse_ticket(ticket)
        ss = recover_ss_from_ticket(p, sk)
        state = init_from_bootstrap(ss, p["epoch"])
        save_state(state)
        print(f"[{DEVICE_ID}] bootstrapped: counter=0, epoch={p['epoch']}")

    # Derive a few rotating keys without contacting server (symmetric ratchet)
    for i in range(3):
        key, state = derive_next_key(state, DEFAULT_PURPOSE)
        save_state(state)
        print(f"[{DEVICE_ID}] derived key {state['counter']-1}: {key.hex()}")

    # Optional: if a new ticket is present, mix it in for PCS
    ticket_path = TICKETS_DIR / f"{DEVICE_ID}.json"
    t_mtime = int(ticket_path.stat().st_mtime) if ticket_path.exists() else 0
    if t_mtime > state.get("last_epoch", 0):
        print(f"[{DEVICE_ID}] found fresher ticket; mixing new entropy")
        ticket = load_ticket()
        p = verify_and_parse_ticket(ticket)
        ss_new = recover_ss_from_ticket(p, sk)
        state = reseed_with_new_ticket(state, ss_new, p["epoch"])
        save_state(state)
        # Derive again post-reseed
        key, state = derive_next_key(state, DEFAULT_PURPOSE)
        save_state(state)
        print(f"[{DEVICE_ID}] post-reseed key {state['counter']-1}: {key.hex()}")

    print(f"[{DEVICE_ID}] done")
