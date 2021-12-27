ssh-keygen -t rsa -b 4096 -m PEM -f access.key
# Don't add passphrase
openssl rsa -in access.key -pubout -outform PEM -out access.key.pub

ssh-keygen -t rsa -b 4096 -m PEM -f refresh.key
# Don't add passphrase
openssl rsa -in refresh.key -pubout -outform PEM -out refresh.key.pub
