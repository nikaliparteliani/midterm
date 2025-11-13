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

If everything is correct, you will receive: >Verified OK


Task 3 – Hashing & HMAC (6 pts)

Create data.txt:











