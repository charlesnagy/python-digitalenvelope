""" Provides a Envelope object to efficiently encrypt streamed data with the speed of symmetric keys 
and the convenience and security of asymmetric keys.

For more info about the structure: http://www.techopedia.com/definition/18859/digital-envelope

Example usage (writing/encryption): 

from DigitalEnvelope import BaseEnvelope

_data = open('any_arbitrary_filename', 'wb')
with BaseEnvelope(data=_data) as _e:
    _e.write('some data you want to encrypt')

# Do this _outside of the with context and save it somewhere with the encrypted file
_encrypted_passphrase = _e.passphrase

Example usage (read/decrypt):

from DigitalEnvelope import BaseEnvelope

with BaseEnvelope(passphrase=self.backup.encrypted_passphrase, data=_input).open(DBAsettings.PRIVATE_KEY_FILE) as _e:
    print _e.read()

Tested with the followings:
CentOS 5.X 6.X
"""
# Workaround for avoiding printing following warning.
#
#/usr/lib/python2.7/site-packages/Crypto/Util/number.py:57: PowmInsecureWarning: Not using mpz_powm_sec.  You should rebuild using libgmp >= 5 to avoid timing attack vulnerability.
#  _warn("Not using mpz_powm_sec.  You should rebuild using libgmp >= 5 to avoid timing attack vulnerability.", PowmInsecureWarning)
import warnings
from Crypto.pct_warnings import PowmInsecureWarning
warnings.filterwarnings('ignore',
                        "Not using mpz_powm_sec.  You should rebuild using libgmp >= 5 to avoid timing attack vulnerability.",
                        category=PowmInsecureWarning,
)
import StringIO
import pickle
import base64
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import ARC4

__author__    = "Karoly 'Charles' Nagy"
__copyright__ = "Copyright 2013, Karoly Nagy"
__licence__   = "GPL v2.0"
__version__   = "0.0.1"
__contact__   = "dr.karoly.nagy@gmail.com"

# Change this to your own PUBLIC_KEY
# Only here for having a fully functional script
# Generated specifically for this script and not used anywhere else
PUBLIC_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDr2jV3eE1hM7Zy32Fbwzs2+QiCHtSMPRHor96FiyOT+zV3FYnRwQoCzEiQPHjKkcY5wKsMIurJO6titN5DC5WYSHmICfRtoQ+ygXI08mtiwXFyGWyIswt/1oY4QAx+W/ZUh/YIBo0JuwZ5eSI5Qlo21lsMSzLTkRXq6DhccwHsDSe4NbAtoPoCOxvrGqOj/NnuNceHylX0EfFtUD0p/vaYq+Mq0q3IUaHRD+sngXKUkDBxeDAYi5j+ElhfuTKw0AGL5x1E68ZJcbsZXXVO/IcxUI8Jvc86TPXID6PkGfK+TxMAIm71EnuW1J9OdjrrCrcrr40fAKXjiFLmEzLrHn5 XXX@XXX"""

def generate_passphrase(length=32):
    """ generate random passphrase
    """
    return base64.encodestring(Crypto.Random.new().read(length))[:length]


class BaseEnvelope(object):
    passphrase = None
    public_key = None
    sealed = None
    _cipher = None
    _rw = None

    def __init__(self, passphrase=None, data=None):
        """ Initializes a Envelope object         
        Args:
        - passphrase: the passphrase for the ARC4 streamcoder (mandatory, if you open an existing envelope)
        - data: A file like object for write encrypted data to or read from (optional, default StringIO.StringIO(''))
        """
        self.passphrase = passphrase or generate_passphrase(32)
        self.data = data or StringIO.StringIO('')
        self._rw = False
        self.public_key = RSA.importKey(PUBLIC_KEY)
        if passphrase:
            self.sealed = True

    def __enter__(self):
        self.seek(0)
        self._cipher = ARC4.new(self.passphrase)
        self._rw = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self._cipher
        self.close()

    def close(self):
        if self.sealed:
            raise TypeError('Envelope has been closed already.')
        self.passphrase = pickle.dumps(self.public_key.encrypt(self.passphrase, 32))
        self.sealed = True
        self._rw = False

    def open(self, private_key_file):
        with open(private_key_file, 'r') as _f:
            _private_key = RSA.importKey(_f.read())
            self.passphrase = _private_key.decrypt(pickle.loads(str(self.passphrase)))

        self.sealed = False
        return self

    def write(self, data):
        if not self._rw:
            raise IOError('Envelope is closed. It can only be written in "with" context.')

        _encrypted = self._cipher.encrypt(data)
        self.data.write(_encrypted)

    def read(self, bytes=None):
        if self.sealed:
            raise IOError('Envelope is sealed. You cannot read it unless it is open.')
        if not self._rw:
            raise IOError('Envelope cannot be read outside of a "with" context.')

        if bytes:
            return self._cipher.decrypt(self.data.read(bytes))
        else:
            return self._cipher.decrypt(self.data.read())

    def seek(self, pos, mode = 0):
        self.data.seek(pos, mode)

    def read_chunks(self, chunksize=4096):
        """Lazy function (generator) to read a data piece by piece.
        Default chunk size: 4096.
        Could be done by the normal read but this way this can be used easily in for statements
        Example:
            for chunk in _obj.read_chunks():
                _out.write(chunk)
        """
        while True:
            data = self.read(chunksize)
            if not data:
                break
            yield data
