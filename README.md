python-digitalenvelope
======================

Digital envelope implementation for Python

Provides a Envelope object to efficiently encrypt streamed data with the speed of symmetric keys 
and the convenience and security of asymmetric keys.

For more info about the structure: http://www.techopedia.com/definition/18859/digital-envelope

## Example usage (writing/encryption):


    from DigitalEnvelope import BaseEnvelope

    _data = open('any_arbitrary_filename', 'wb')
    with BaseEnvelope(data=_data) as _e:
        _e.write('some data you want to encrypt')

    # Do this _outside of the with context and save it somewhere with the encrypted file
    _encrypted_passphrase = _e.passphrase

## Example usage (read/decrypt):

    from DigitalEnvelope import BaseEnvelope

    with BaseEnvelope(passphrase=self.backup.encrypted_passphrase, data=_input).open(DBAsettings.PRIVATE_KEY_FILE) as _e:
        print _e.read()

You can find me on [Twitter](https://twitter.com/charlesnagy "Charlesnagy Twitter"), [My Blog](http://charlesnagy.info/ "Charlesnagy.info") or [LinkedIn](http://www.linkedin.com/in/nkaroly "Károly Nagy - MySQL DBA")
