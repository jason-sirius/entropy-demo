import time, json, pathlib
from device import ensure_keys, register_public_key, derive_epoch_key_from_ticket, TICKETS_DIR

DEVICE_ID = "DT-042"   # change per device
EPOCH_LEN = 60

if __name__ == "__main__":
    pk, sk = ensure_keys()
    register_public_key(pk)

    print(f"[{DEVICE_ID}-loop] Starting, deriving new key every 60s")
    while True:
        ticket_path = TICKETS_DIR / f"{DEVICE_ID}.json"
        if ticket_path.exists():
            ticket = json.loads(ticket_path.read_text())
            try:
                key = derive_epoch_key_from_ticket(ticket, sk)
                print(f"[{DEVICE_ID}-loop] {time.ctime()} derived key: {key.hex()}")
            except Exception as e:
                print(f"[{DEVICE_ID}-loop] Ticket invalid: {e}")
        else:
            print(f"[{DEVICE_ID}-loop] No ticket found yet")
        time.sleep(EPOCH_LEN)