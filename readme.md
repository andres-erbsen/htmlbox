# htmlbox - encrypt HTML, decrypt in browser
## What htmlbox does
Given a (HTML or plain text) file and a password, htmlbox encrypts the file and
wraps the result into javascript which can decrypt it in (browser given the correct password, of course). See an [example](http://pastehtml.com/view/c24sc3g5q.html) (the password is `xkcd`).

- multiple passwords support
- AES for encryption and SHA25 for key deriviation (from [CryptoJS])

## What htmlbox does **not** do
- Store store the plaintext in HTML source
- Authentication
 - if somebody knows contents of a message, they can generate a modified version of it without knowing the key

## Dependencies
- [Python] (>= 2.5 && < 3.0) 
- [PyCrypto]
- (tested on Arch and Ubuntu Linux)

## Installation
- `git clone git://github.com/andres-erbsen/htmlbox.git`
- `cd htmlbox`
- `export PATH=$PATH:$(pwd)` # and maybe add this to your `.profile`

## Usage
- Encrypt `secret.html` using password `whocares` and save the results to `attatchment.html` by executing:
  `cat secret.html | htmlbox.py whocares > attatchment.html`
- Use passwords `usual` and `tHe long pwd` instead:
  `cat secret.html | htmlbox.py usual "tHe long pwd" > attatchment.html`
- Convert plaintext to a html paragraph on the go: encrypt list of running processes:
  `ps -e | htmlbox.py -p whocares > ps_e.html`
- customize page title: `-t "Very Funny"`
- customize password prompt: `-m "No plaintext the source, don't bother"`

  [Python]:   http://python.org/download/
  [CryptoJS]: https://code.google.com/p/crypto-js/
  [PyCrypto]: http://pypi.python.org/pypi/pycrypto
