# vim: sw=4:ts=4:et:cc=120
#
# cryptography functions used by ACE
#

import logging
import os.path
import random
import struct

import Crypto.Random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

import saq

CHUNK_SIZE = 64 * 1024

def _get_validation_hash_path():
    """Returns the full path to the file containing the encryption password validation hash."""
    return os.path.join(saq.SAQ_HOME, 'etc', 'validation_hash')

def _get_validation_hash():
    """Returns the validation hash of the encryption password, or None if it has not been set."""
    try:
        with open(_get_validation_hash_path(), 'r') as fp:
            return fp.read().strip().lower()
    except Exception as e:
        logging.warning("unable to load encryption password validation hash: {}".format(e))
        return None

def _compute_validation_hash(password):
    assert isinstance(password, str)

    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(password.encode())
    initial_digest = h.digest()

    h = SHA256.new()
    h.update(initial_digest)
    return h.hexdigest().lower()

def test_encryption_password(password):
    """Tests the given password against what is saved in the global section of the config file as the encryption password.
       Returns True if the password is correct, False if it is incorrect or if the password is not set."""
    assert isinstance(password, str)

    validation_hash = _get_validation_hash()
    if validation_hash is None:
        return False
    
    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(password.encode())
    initial_digest = h.digest() # this would be the AES key

    h = SHA256.new()
    h.update(initial_digest)
    if h.hexdigest().lower() != validation_hash:
        return False

    return True

def set_encryption_password(password):
    """Sets the encryption password for the system by saving the validation hash."""
    assert isinstance(password, str)

    try:
        with open(_get_validation_hash_path(), 'w') as fp:
            fp.write(_compute_validation_hash(password))
        logging.info("updated validation hash")
    except Exception as e:
        logging.warning("unable to save encryption password validation hash: {}".format(e))

def get_aes_key(password):
    """Returns the binary key to be used to actually encrypt and decrypt."""
    assert isinstance(password, str)

    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(password.encode())
    return h.digest()

# https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
def encrypt(source_path, target_path, password=None):
    """Encrypts the given file at source_path with the given password and saves the results in target_path.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    encryptor = AES.new(password, AES.MODE_CBC, iv)
    file_size = os.path.getsize(source_path)

    with open(source_path, 'rb') as fp_in:
        with open(target_path, 'wb') as fp_out:
            fp_out.write(struct.pack('<Q', file_size))
            fp_out.write(iv)

            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                fp_out.write(encryptor.encrypt(chunk))

def encrypt_chunk(chunk, password=None):
    """Encrypts the given chunk of data and returns the encrypted chunk.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    iv = Crypto.Random.OSRNG.posix.new().read(AES.block_size)
    encryptor = AES.new(password, AES.MODE_CBC, iv)

    original_size = len(chunk)

    if len(chunk) % 16 != 0:
        chunk += b' ' * (16 - len(chunk) % 16)

    return struct.pack('<Q', original_size) + iv + encryptor.encrypt(chunk)

def decrypt(source_path, target_path=None, password=None):
    """Decrypts the given file at source_path with the given password and saves the results in target_path.
       If target_path is None then output will be sent to standard output.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    with open(source_path, 'rb') as fp_in:
        original_size = struct.unpack('<Q', fp_in.read(struct.calcsize('Q')))[0]
        iv = fp_in.read(16)
        decryptor = AES.new(password, AES.MODE_CBC, iv)

        with open(target_path, 'wb') as fp_out:
            while True:
                chunk = fp_in.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break

                fp_out.write(decryptor.decrypt(chunk))

            fp_out.truncate(original_size)

def decrypt_chunk(chunk, password=None):
    """Decrypts the given encrypted chunk with the given password and returns the decrypted chunk.
       If password is None then saq.ENCRYPTION_PASSWORD is used instead.
       password must be a byte string 32 bytes in length."""

    if password is None:
        password = saq.ENCRYPTION_PASSWORD

    assert isinstance(password, bytes)
    assert len(password) == 32

    original_size = struct.unpack('<Q', chunk[0:struct.calcsize('Q')])[0]
    iv = chunk[struct.calcsize('Q'):struct.calcsize('Q') + 16]
    chunk = chunk[struct.calcsize('Q') + 16:]
    decryptor = AES.new(password, AES.MODE_CBC, iv)
    result = decryptor.decrypt(chunk)
    return result[:original_size]
