import time, json, pathlib
import oqs
from server import load_registry, new_ticket_for_device, TICKETS_DIR

EPOCH_LEN = 60

if __name__ == "__main__":
    print("[server-loop] Starting, generating new tickets every 60s")
    while True:
        reg = load_registry()
        if not reg:
            print("[server-loop] No device keys in registry/")
        else:
            for device_id, pk in reg.items():
                ticket = new_ticket_for_device(device_id, pk)
                out_path = TICKETS_DIR / f"{device_id}.json"
                out_path.write_text(json.dumps(ticket))
                print(f"[server-loop] Issued ticket for {device_id} at {time.ctime()}")
        time.sleep(EPOCH_LEN)