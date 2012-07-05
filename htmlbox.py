#!/usr/bin/env python2
from sys           import stdin, stdout, stderr
from optparse      import OptionParser
from os            import urandom
from hashlib       import sha256
from Crypto.Cipher import AES
from base64        import b64encode
import sys, os

def jsdecrypter(**replacements):
    pathname = os.path.dirname(sys.argv[0])
    package = open(os.path.join(pathname,'decrypter.html')).read()
    for key in replacements:
        package = package.replace('$%s$'%key ,replacements[key])
    return package

def pad_PKCS7(message, bs=16):
    n = (-len(message)-1) % bs + 1 # bytes of padding needed
    return message + n*chr(n)

def enc(k,iv,p):
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad_PKCS7( p ))

def main():
    parser = OptionParser(usage="usage: %prog [options] password1 [passwords...]")
    parser.add_option('--message',   '-m',   default="Enter password:",
            help="Message displayed above password prompt")
    parser.add_option('--title',     '-t',   default="",
            help="Title of the resulting HTML document")
    parser.add_option('--plaintext', '-p',   action="store_true",
            help="Treat input as plaintext instead of HTML")
    parser.add_option('--hashes', '-H',   action="store_true",
            help="Input hex-encoded SHA256 hashes instead of passwords")
    opts, passwords = parser.parse_args()
    
    if not passwords:
        parser.error("No passwords/hashes specified.")

    rawtext = stdin.read()
    if opts.plaintext:
        rawtext = ( '<html><head></head><body><p>\n' + # headers...
                     rawtext.replace('\n','<br/>\n') + # newlines to html
                    '</p></body></html>' )             # close the tags

    key = urandom(32) # masterkey with which the input will be encrypted
    iv = urandom(16)
    ct = enc(key, iv, rawtext)

    # Hash the passwords or decode hashes
    hashes = []
    if opts.hashes:
        for password in passwords:
            hashes.append( password.decode('hex' ) )
    else:
        for password in passwords:
            hashes.append( sha256(password).digest() )

    tickets = [] # master key encrypted with users' passwords' hashes
    for secret in hashes:
        ident  = sha256(secret).digest() # used for dictionary lookup
        ticket_iv = urandom(16)
        ticket_ct = enc(secret, ticket_iv, key)
        tickets.append( '"%s": {"ct": "%s", "iv": "%s"}' % ( # part of JS code
                          b64encode(ident)
                                    , b64encode(ticket_ct)
                                                 , b64encode(ticket_iv)
              ))
    keyring = '{' + ', '.join(tickets) + '}' # JS code for keyring

    stdout.write(jsdecrypter( ciphertext = b64encode(ct)
                            , keyring    = keyring
                            , iv         = b64encode(iv)
                            , title      = opts.title
                            , message    = opts.message
                            ))

if __name__ == "__main__":
    main()
