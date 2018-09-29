# vim: sw=4:ts=4:et

import logging

import saq

from saq.crypto import encrypt_chunk, decrypt_chunk, get_aes_key
from saq.test import *

class ACECryptoTestCase(ACEBasicTestCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.old_password = saq.ENCRYPTION_PASSWORD
        saq.ENCRYPTION_PASSWORD = get_aes_key('test')

    def tearDown(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        saq.ENCRYPTION_PASSWORD = self.old_password
    
    def test_anp_000_encrypt_chunks(self):
        chunk = b'1234567890'
        encrypted_chunk = encrypt_chunk(chunk)
        self.assertNotEquals(chunk, encrypted_chunk)
        decrypted_chunk = decrypt_chunk(encrypted_chunk)
        self.assertEquals(chunk, decrypted_chunk)

    def test_anp_001_encrypt_empty_chunks(self):
        chunk = b''
        encrypted_chunk = encrypt_chunk(chunk)
        self.assertNotEquals(chunk, encrypted_chunk)
        decrypted_chunk = decrypt_chunk(encrypted_chunk)
        self.assertEquals(chunk, decrypted_chunk)
