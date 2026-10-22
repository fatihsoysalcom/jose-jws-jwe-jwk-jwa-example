import json
from jose import jwt, jwe
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# --- 1. JWK (JSON Web Key) Concept: Key Generation ---

# For JWS (Symmetric Key)
# A simple string secret acts as a symmetric key for HS256 algorithm.
# In a real application, this would be a securely generated, strong random string.
JWS_SECRET = "super-secret-key-for-signing-jwt-1234567890"

# For JWE (Asymmetric Key Pair - RSA)
# Generate an RSA private key for encryption/decryption.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize keys to PEM format for use with jose library.
# In a real application, these would be loaded from files or a key management system.
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

print("--- JWK (JSON Web Key) Details ---")
print(f"JWS Symmetric Key (HS256): '{JWS_SECRET}' (represented as a string)")
print(f"JWE RSA Public Key (PEM):
{public_pem}")
print(f"JWE RSA Private Key (PEM):
{private_pem}")
print("-----------------------------------\n")

# --- 2. JWS (JSON Web Signature) Example ---
# Demonstrates signing a JWT for integrity (what most people mean by "JWT")

print("--- JWS (JSON Web Signature) Example ---")

# JWS Header: Specifies the algorithm (JWA) and token type
jws_header = {
    "alg": "HS256", # JWA: HMAC using SHA-256
    "typ": "JWT"
}

# JWS Payload: The claims/data to be signed
jws_payload = {
    "user_id": "123",
    "role": "admin",
    "iat": 1678886400, # Issued At timestamp
    "exp": 1678890000  # Expiration timestamp
}

# Encode (Sign) the JWT
# The jwt.encode function takes the payload, secret (JWK), and algorithm (JWA)
signed_jwt = jwt.encode(jws_payload, JWS_SECRET, algorithm=jws_header["alg"], headers=jws_header)
print(f"Signed JWT (JWS): {signed_jwt}\n")

# A JWT (JWS) consists of three parts: Header.Payload.Signature
header_b64, payload_b64, signature_b64 = signed_jwt.split('.')
print(f"JWS Header (Base64url encoded): {header_b64}")
print(f"JWS Payload (Base64url encoded): {payload_b64}")
print(f"JWS Signature (Base64url encoded): {signature_b64}\n")

# Decode (Verify) the JWT
# The jwt.decode function verifies the signature using the secret (JWK) and algorithm (JWA)
try:
    decoded_jws_payload = jwt.decode(signed_jwt, JWS_SECRET, algorithms=[jws_header["alg"]])
    print(f"Decoded JWS Payload: {json.dumps(decoded_jws_payload, indent=2)}\n")
    print("JWS verification successful: The token's integrity is confirmed.\n")
except Exception as e:
    print(f"JWS verification failed: {e}\n")

# --- 3. JWE (JSON Web Encryption) Example ---
# Demonstrates encrypting a JWT for confidentiality

print("--- JWE (JSON Web Encryption) Example ---")

# JWE Header: Specifies encryption algorithm (JWA) and key management algorithm (JWA)
jwe_header = {
    "alg": "RSA-OAEP-256", # JWA: Algorithm for key encryption (e.g., RSA-OAEP-256)
    "enc": "A256GCM",      # JWA: Algorithm for content encryption (e.g., AES-256 GCM)
    "typ": "JWT",
    "cty": "JWT"           # Content Type: Nested JWT (optional, but good practice for JWE of JWT)
}

# JWE Payload: The data to be encrypted (could be another JWS token, or just JSON)
jwe_payload = {
    "sensitive_data": "This information is highly confidential!",
    "transaction_id": "TXN-007",
    "amount": 1000.50
}

# Encrypt the payload using the public key (JWK)
# The jwe.encrypt function takes the payload, public key (JWK), and algorithms (JWA)
encrypted_jwe = jwe.encrypt(
    json.dumps(jwe_payload).encode('utf-8'), # Payload must be bytes
    public_pem, # Recipient's public key (JWK)
    algorithm=jwe_header["alg"],
    encryption=jwe_header["enc"],
    headers=jwe_header
)
print(f"Encrypted JWE: {encrypted_jwe}\n")

# A JWE consists of five parts: Header.EncryptedKey.IV.Ciphertext.AuthenticationTag
header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = encrypted_jwe.split('.')
print(f"JWE Header (Base64url encoded): {header_b64}")
print(f"JWE Encrypted Key (Base64url encoded): {encrypted_key_b64}")
print(f"JWE Initialization Vector (Base64url encoded): {iv_b64}")
print(f"JWE Ciphertext (Base64url encoded): {ciphertext_b64}")
print(f"JWE Authentication Tag (Base64url encoded): {tag_b64}\n")

# Decrypt the JWE using the private key (JWK)
# The jwe.decrypt function takes the JWE token and the private key (JWK)
try:
    decrypted_jwe_payload_bytes = jwe.decrypt(encrypted_jwe, private_pem)
    decrypted_jwe_payload = json.loads(decrypted_jwe_payload_bytes.decode('utf-8'))
    print(f"Decrypted JWE Payload: {json.dumps(decrypted_jwe_payload, indent=2)}\n")
    print("JWE decryption successful: Confidentiality maintained.\n")
except Exception as e:
    print(f"JWE decryption failed: {e}\n")

print("--- Summary ---")
print("This example demonstrates:")
print("  - JWS: Signing for integrity using a symmetric key (HS256).")
print("  - JWE: Encrypting for confidentiality using an asymmetric key pair (RSA-OAEP-256, A256GCM).")
print("  - JWK: How keys are used (symmetric string, RSA PEM format).")
print("  - JWA: The algorithms specified in headers for both signing and encryption.")
