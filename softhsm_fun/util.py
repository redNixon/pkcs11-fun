#!/usr/bin/python3
from subprocess import Popen, PIPE, STDOUT
import re


def init_token(user_pin='12345', so_pin='54321', label='softhsmfun'):
    process = Popen(['softhsm2-util', '--init-token', '--free', '--label', '%s' % label,
                     '--pin', '%s' % user_pin,
                     '--so-pin', '%s' % so_pin], stdout=PIPE, stderr=STDOUT)
    stdout, stderr = process.communicate()
    result = re.search(r'.*reassigned\sto\sslot\s(\d+)', stdout.decode('utf-8'))
    if result:
        return result.groups()[0]
    else:
        return None
