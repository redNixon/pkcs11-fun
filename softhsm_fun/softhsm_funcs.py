#!/usr/bin/env python3
import pkcs11
import sqlite3
import base64
import argparse
from util import init_token


class Database():
    def __init__(self, dbName='hsm_fun.db'):
        self.connection = sqlite3.connect('hsmtest.db')
        self.cursor = self.connection.cursor()
        self.cursor.execute('''CREATE TABLE if not exists
                                keys (
                                    id integer primary key not null,
                                    label text,
                                    key text)''')
        self.cursor.execute('''CREATE TABLE if not exists
                                crypttex (
                                    id integer primary key not null,
                                    label text,
                                    cleartext text,
                                    iv text,
                                    ciphertext text)''')
        self.connection.commit()


class PKSession(object):
    def __init__(self, label):
        self.lib = pkcs11.lib('/usr/local/lib/softhsm/libsofthsm2.so')
        self.token = self.lib.get_token(token_label=label)
        super().__init__()


class Key(PKSession):
    def __init__(self):
        super().__init__()

    def get_key(self, label):
            key = self.session.get_key(label=label)
            return key

    @classmethod
    def new_key(self):
        raise NotImplementedError


class Crypt(object):
    def __init__(self):
        super().__init__()

    def cryptData(self, db, token, data, label):
        with token.open(rw=True, user_pin='1234') as session:
            # Encrypt our data
            key = self.get_key(session, label)
            iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
            iv_encoded = base64.urlsafe_b64encode(iv)
            crypttext = key.encrypt(data, mechanism_param=iv)
            db.cursor.execute('insert into crypttex values(?,?,?,?,?)', (None, label, data, iv_encoded,
                                                                         base64.urlsafe_b64encode(crypttext)))
            db.connection.commit()
            return crypttext, session

    def decryptData(self, db, token, label):
        with token.open(rw=True, user_pin='1234') as session:
            # decrypt our data
            iv_en, edata, data = db.cursor.execute('select iv, edata, data from crypttex where label=?',
                                                   (label,)).fetchone()
            key = self.get_key(session, label)
            iv = base64.urlsafe_b64decode(iv_en)
            cdata = base64.urlsafe_b64decode(edata)
            crypttext = key.decrypt(cdata, mechanism_param=iv)
            return crypttext


class RSA(object):
    def __init__(self):
        super().__init__()

    def new_key(self, label):
        # Generate a RSA key
        pub, priv = self.session.generate_keypair(pkcs11.KeyType.RSA, 4096, label=label, store=True)


class AES(object):
    def __init__(self):
        super().__init__()

    def new_key(self, label):
        # Generate an AES key in this session
        key = self.session.generate_key(pkcs11.KeyType.AES, 256, label=label)
        return key


def main():

    # Common flags
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--label', action="store")

    # Encryption/Decryption operations
    crypt_parser = argparse.ArgumentParser(add_help=False)
    crypt_parser.add_argument(
        '--iv', action='store', dest='iv', default=None,
        help='Define the initialization vector.')
    crypt_parser.add_argument(
        '--crypt', action='store_true', dest='crypt', default=False,
        help='Generate AES key.')
    crypt_parser.add_argument(
        '--decrypt', action='store_true', dest='decrypt', default=False,
        help='Generate AES key.')
    crypt_parser.add_argument(
        '--data', action='store', dest='data', default=None, type=str,
        help='Label for things')

    # Key Operations
    key_parser = argparse.ArgumentParser(add_help=False)
    key_parser.add_argument(
        '--new-key', action='store_true', dest='new_key', default=False,
        help='Generate a new key.')
    key_parser.add_argument(
        '--store', action='store_true', default=False,
        help='Store the key(if a new one was created).')

    # Main Parser
    parser = argparse.ArgumentParser(description='HSM scratchpad.', parents=[common_parser])
    subparsers = parser.add_subparsers(help='commands')

    # Token/Slot init fucntions
    token_parser = subparsers.add_parser(
        'init_slot', help='Initialize a new slot and token')
    token_parser.add_argument(
        '--user-pin', dest='user_pin', action='store', help='User Pin')
    token_parser.add_argument(
        '--so-pin', dest='so_pin', action='store', help='Security Officer Pin')
    token_parser.add_argument(
        '--slot', dest='slot', action='store', help='Optionally define a slot, defaults to --free')
    token_parser.set_defaults(func=init_token)

    # RSA functions
    rsa_parser = subparsers.add_parser(
        'rsa', help='RSA Functions', parents=[crypt_parser, key_parser])
    rsa_parser.set_defaults(func=main)

    # AES functions
    aes_parser = subparsers.add_parser(
        'aes', help='AES Functions', parents=[crypt_parser, key_parser])
    aes_parser.set_defaults(func=main)

    args = parser.parse_args()
    args.func


if __name__ == '__main__':
    main()
