#!/usr/bin/env python3
import pkcs11
import sqlite3
import base64
import argparse


class Database():
    def __init__(self, dbName='hsm_fun.db'):
        self.connection = sqlite3.connect('hsmtest.db')
        self.cursor = self.connection.cursor()
        self.cursor.execute('''CREATE TABLE if not exists keys (id integer primary key not null, label text,
                            key text, iv text)''')
        self.cursor.execute('''CREATE TABLE if not exists crypttex (id integer primary key not null,
                            label text, data text, iv text, edata text)''')
        self.connection.commit()


def getAESKey(session, label):
        key = session.get_key(label=label)
        return key


def createRSAKey(db, token, label, store):
    with token.open(rw=True, user_pin='1234') as session:
        # Generate an AES key in this session
        pub, priv = session.generate_keypair(pkcs11.KeyType.RSA, 4096, label=label, store=True)


def createAESKey(db, token, label, store):
    with token.open(rw=True, user_pin='1234') as session:
        # Generate an AES key in this session
        key = session.generate_key(pkcs11.KeyType.AES, 256, store=store, label=label)
        return key


def cryptData(db, token, data, label):
    with token.open(rw=True, user_pin='1234') as session:
        # Encrypt our data
        key = getAESKey(session, label)
        iv = session.generate_random(128)  # AES blocks are fixed at 128 bits
        iv_encoded = base64.urlsafe_b64encode(iv)
        crypttext = key.encrypt(data, mechanism_param=iv)
        db.cursor.execute('insert into crypttex values(?,?,?,?,?)', (None, label, data, iv_encoded,
                                                                     base64.urlsafe_b64encode(crypttext)))
        db.connection.commit()
        return crypttext, session


def decryptData(db, token, label):
    with token.open(rw=True, user_pin='1234') as session:
        # Encrypt our data
        iv_en, edata, data = db.cursor.execute('select iv, edata, data from crypttex where label=?', (label,)
                                               ).fetchone()
        key = getAESKey(session, label)
        iv = base64.urlsafe_b64decode(iv_en)
        cdata = base64.urlsafe_b64decode(edata)

        crypttext = key.decrypt(cdata, mechanism_param=iv)
        print('clear: %s' % data)
        print('crypted: %s' % crypttext)
        print(crypttext == data)


def main():
    parser = argparse.ArgumentParser(description='\
    HSM scratchpad.')
    parser.add_argument(
        '--gen-rsa', action='store_true', dest='gen_rsa', default=False,
        help='Generate AES key.')
    parser.add_argument(
        '--crypt', action='store_true', dest='crypt', default=False,
        help='Generate AES key.')
    parser.add_argument(
        '--decrypt', action='store_true', dest='decrypt', default=False,
        help='Generate AES key.')
    parser.add_argument(
        '--gen-aes', action='store_true', dest='gen_aes', default=False,
        help='Generate AES key.')
    parser.add_argument(
        '--store', action='store_true', default=False,
        help='Store the key.')
    parser.add_argument(
        '--slot', action='store', default=None,
        help='Store the key.')
    parser.add_argument(
        '--label', action='store', dest='label', default=None, type=str,
        help='Label for things')
    parser.add_argument(
        '--data', action='store', dest='data', default=None, type=str,
        help='Label for things')
    args = parser.parse_args()

    # Initialise our PKCS#11 librar
    lib = pkcs11.lib('/usr/local/lib/softhsm/libsofthsm2.so')
    token = lib.get_token(token_label=args.slot)
    db = Database()
    if args.gen_aes:
        createAESKey(db, token, args.label, args.store)
    if args.gen_rsa:
        createRSAKey(db, token, args.label, args.store)
    elif args.crypt:
        cryptData(db, token, args.data, args.label)
    elif args.decrypt:
        decryptData(db, token, args.label)


if __name__ == '__main__':
    main()
