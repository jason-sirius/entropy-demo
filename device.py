import os, json, base64, hmac, hashlib, time, pathlib
from typing import Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import oqs

# ===== Device constants (DEMO) =====
DEVICE_ID      = "DT-042"
GROUP_ID       = "ops-alpha"
PURPOSE        = b"vpn-psk"
COHORT_SECRET  = b"sealed_cohort_secret_32bytes_______"   # sealed in TPM/SE in real life
AUTH_MAC_KEY   = b"server_auth_mac_key_64bytes________"   # shared with server for payload HMAC (demo)
KEYS_DIR       = pathlib.Path("keys")
REG_DIR        = pathlib.Path("registry")
TICKETS_DIR    = pathlib.Path("tickets")

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
    # Generate new Kyber-1024 keys
    with oqs.KeyEncapsulation("Kyber1024") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    pub_path.write_bytes(pk)
    priv_path.write_bytes(sk)
    return pk, sk

def register_public_key(pk: bytes):
    """Write the public key to the shared registry for the server to read (demo)."""
    REG_DIR.mkdir(parents=True, exist_ok=True)
    (REG_DIR / f"{DEVICE_ID}.pk").write_bytes(pk)

def _kem_for_decapsulation(sk: bytes):
    """Get a KeyEncapsulation object initialized with secret key (handles API versions)."""
    try:
        return oqs.KeyEncapsulation("Kyber1024", secret_key=sk)  # modern API
    except TypeError:
        kem = oqs.KeyEncapsulation("Kyber1024")
        if hasattr(kem, "import_secret_key"):
            kem.import_secret_key(sk)  # older API
            return kem
        raise RuntimeError("Your oqs binding doesn’t support loading a secret key.")

def _kem_decap(kem, ct: bytes) -> bytes:
    if hasattr(kem, "decap_secret"):   # modern API
        return kem.decap_secret(ct)
    if hasattr(kem, "decapsulate"):    # older API
        return kem.decapsulate(ct)
    raise RuntimeError("oqs KeyEncapsulation has no decapsulation method.")

def derive_epoch_key_from_ticket(ticket: dict, sk: bytes) -> bytes:
    """Verify ticket HMAC, decapsulate Kyber ct, and derive final working key."""
    payload_bytes = b64u_dec(ticket["payload_b64"])
    tag           = b64u_dec(ticket["tag_b64"])

    # Verify integrity/auth of payload (symmetric demo)
    expected = hmac.new(AUTH_MAC_KEY, payload_bytes, hashlib.sha512).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Invalid HMAC (payload tampered or forged).")

    p = json.loads(payload_bytes.decode())
    # Audience binding
    if p["aud"] != DEVICE_ID:
        raise ValueError(f"Wrong audience: expected {DEVICE_ID}, got {p['aud']}")

    # Freshness checks
    now = int(time.time())
    epoch = p["epoch"]; ttl = p["ttl_s"]
    if not (epoch <= now < epoch + ttl):
        raise ValueError("Ticket outside acceptance window.")

    # --- KEM decapsulation ---
    ct = b64u_dec(p["ct_b64"])
    kem = _kem_for_decapsulation(sk)
    try:
        ss = _kem_decap(kem, ct)
    finally:
        if hasattr(kem, "free"):
            kem.free()
    # -------------------------

    # Final working key = HKDF( ss || cohort_secret )
    info = b"purpose=" + PURPOSE + b";group=" + GROUP_ID.encode() + b";epoch=" + str(epoch).encode()
    ikm  = ss + COHORT_SECRET
    hkdf = HKDF(algorithm=hashes.SHA512(), length=32, salt=str(epoch).encode(), info=info)
    key  = hkdf.derive(ikm)
    return key

if __name__ == "__main__":
    pk, sk = ensure_keys()
    register_public_key(pk)
    ticket_path = TICKETS_DIR / f"{DEVICE_ID}.json"
    if not ticket_path.exists():
        print(f"[{DEVICE_ID}] Waiting for ticket at {ticket_path} ...")
        print("Run: python server.py and then re-run this script.")
        raise SystemExit(1)
    ticket = json.loads(ticket_path.read_text())
    key = derive_epoch_key_from_ticket(ticket, sk)
    print(f"[{DEVICE_ID}] Derived working key (hex): {key.hex()}")
