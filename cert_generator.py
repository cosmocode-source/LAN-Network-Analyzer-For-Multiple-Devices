import subprocess
import os

IP = input("Enter Server IP: ").strip()

def run(cmd):
    print(f"\n>> {cmd}")
    subprocess.run(cmd, shell=True, check=True)

# STEP 0 — Update SAN file
san_content = f"""
[req]
distinguished_name=req
[san]
subjectAltName=IP:{IP}
"""

with open("san.cnf", "w") as f:
    f.write(san_content)

print("\n[+] san.cnf updated")

# STEP 1 — CA (only if not exists)
if not os.path.exists("ca_key.pem"):
    run("openssl genrsa -out ca_key.pem 2048")
    run('openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 -out ca_cert.pem -subj "/CN=MyRootCA"')
else:
    print("[+] CA already exists, skipping...")

# STEP 2 — Server Key
run("openssl genrsa -out server_key.pem 2048")

# STEP 3 — Server CSR
run(f'openssl req -new -key server_key.pem -out server.csr -subj "/CN={IP}"')

# STEP 4 — Sign Server Cert
run("openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out server_cert.pem -days 365 -sha256 -extfile san.cnf -extensions san")

# STEP 5 — Client Key
run("openssl genrsa -out client_key.pem 2048")

# STEP 6 — Client CSR
run('openssl req -new -key client_key.pem -out client.csr -subj "/CN=client1"')

# STEP 7 — Sign Client Cert
run("openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365 -sha256")

print("\n[✓] All certificates generated successfully.")