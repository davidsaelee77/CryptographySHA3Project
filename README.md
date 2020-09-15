# CryptographySHA3Project
TCSS 487 Cryptography - SHA3, KMAC256, KMAXOF256 encryption program.

OBJECTIVE:

- Implement (in Java) a library and an app for asymmetric encryption and digital signatures at the 256-bit security level.

- Algorithms:
  - SHA-3 derived function KMACXOF256;
  - ECDHIES encryption and Schnorr signatures;

OUTCOME:

1. Computes a plain cryptographic hash of a given file.
2. Encrypts a given data file symmetrically under a given passphrase.  Decrypts a given symmetric cryptogram under a given passphrase.
3. Generates an elliptic key pair from a given passphrase and writes the public key to a file.
4. (DOES NOT WORK, IN PROGRESS) Encrypt a data file under a given elliptic public key file. Decrypt a given elliptic-encrypted file from a given password.
5. (DOES NOT WORK, IN PROGRESS) Sign a given file from a given password and write the signature to a file. Verify a given data file and its signature file under a given public key file.
