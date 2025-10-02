from device import derive_epoch_key
import server

ticket = server.new_entropy_ticket()

cohort_secret = b"sealed_cohort_secret_32bytes_______"

# Device A
key_a = derive_epoch_key(ticket, b"vpn-psk", b"ops-alpha", b"DT-001")

# Device B
key_b = derive_epoch_key(ticket, b"vpn-psk", b"ops-alpha", b"DT-002")

print("Device A key:", key_a.hex())
print("Device B key:", key_b.hex())
print("Keys match? ", key_a == key_b)
