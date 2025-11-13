Applied Cryptography – Midterm Lab Exam (Weeks 1–4)

Task 1 – AES Encryption (5 pts)
Create the file:
>echo "This file contains top secret information." > secret.txt

ncrypt using AES-128-CBC with a passphrase:
>openssl enc -aes-128-cbc -salt -in secret.txt -out secret.enc -pass pass:NikaStrongPass123

Decrypt the encrypted file:
>openssl enc -d -aes-128-cbc -in secret.enc -out secret_decrypted.txt -pass pass:NikaStrongPass123

Show that matches original:
>diff secret.txt secret_decrypted.txt


Task 2 – ECC Signature Verification (4.5 pts)

ECC private key (prime256v1):
>openssl ecparam -name prime256v1 -genkey -noout -out ecc_private.pem

ECC public key:
>openssl ec -in ecc_private.pem -pubout -out ecc_public.pem

Sign and verify a message Create ecc.txt:
>echo "Elliptic Curves are efficient." > ecc.txt

Sign with private key (ECDSA + SHA-256):

>openssl dgst -sha256 -sign ecc_private.pem -out ecc.sig ecc.txt

>openssl base64 -in ecc.sig -out ecc.sig.b64

Verify with public key
>openssl dgst -sha256 -verify ecc_public.pem -signature ecc.sig ecc.txt

If everything is correct, you will receive: Verified OK


Task 3 – Hashing & HMAC (6 pts)

Create data.txt:
>echo "Never trust, always verify." > data.txt

Hash using OpenSSL:
>openssl dgst -sha256 data.txt

>openssl dgst -sha256 data.txt > data.txt.sha256

HMAC using SHA-256 (2 pts):
>openssl dgst -sha256 -hmac "secretkey123" data.txt

>openssl dgst -sha256 -hmac "secretkey123" data.txt > data.txt.hmac

Integrity Check (2 pts):

Change one letter in data.txt
>echo "Never trust, always verifx." > data_modified.txt

Recompute HMAC for modified file:
>openssl dgst -sha256 -hmac "secretkey123" data_modified.txt > data_modified.txt.hmac

Comparison:
>cat data.txt.hmac

>cat data_modified.txt.hmac

The hashes should be completely different, even though only one letter inside has changed (y → x).

When I changed a single letter in data.txt and recomputed the HMAC using the same key (secretkey123), the resulting HMAC value was completely different.
This shows that HMAC is highly sensitive to any change in the message.
HMAC is important because it provides:

Integrity – detects any modification of the message.

Authentication – only someone who knows the secret key can generate a valid HMAC.
Therefore, even a 1-character change breaks the integrity and produces a different HMAC.


Task 4 – Diffie-Hellman Key Exchange (4.5 pts)

Generate DH parameters (shared between Alice & Bob):
>openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:2048 -out dhparams.pem

Generate Alice’s private key
>openssl genpkey -paramfile dhparams.pem -out alice_priv.pem

Extract Alice’s public key:
>openssl pkey -in alice_priv.pem -pubout -out alice_pub.pem

Generate Bob’s private key
>openssl genpkey -paramfile dhparams.pem -out bob_priv.pem


Extract Bob’s public key:
>openssl pkey -in bob_priv.pem -pubout -out bob_pub.pem

Derive shared secret (Alice side):
>openssl pkeyutl -derive -inkey alice_priv.pem -peerkey bob_pub.pem -out alice_secret.bin

 base64 view:
>openssl base64 -in alice_secret.bin -out alice_secret.b64

>cat alice_secret.b64

Derive shared secret (Bob side):
>openssl pkeyutl -derive -inkey bob_priv.pem -peerkey alice_pub.pem -out bob_secret.bin

base64 view:
>openssl base64 -in bob_secret.bin -out bob_secret.b64
>cat bob_secret.b64

comp:
> diff alice_secret.b64 bob_secret.b64

Diffie-Hellman key exchange is widely used in real-world secure communication protocols.
In TLS (HTTPS), an ephemeral Diffie-Hellman (DHE/ECDHE) exchange is used during the handshake to securely agree on a shared symmetric key between client and server, even if an attacker is monitoring the traffic.
It is also a core building block in secure messaging protocols such as the Signal Protocol, where Diffie-Hellman is used in the "double ratchet" mechanism to provide forward secrecy and post-compromise security.
Diffie-Hellman is important because it allows two parties to derive a shared secret over an insecure channel without ever sending the secret itself, making passive eavesdropping useless.











