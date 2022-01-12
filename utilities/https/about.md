https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https

The general idea is that when the client establishes a connection with the server and requests an encrypted connection, the server responds with its SSL Certificate. The certificate acts as identification for the server, as it includes the server name and domain.

To ensure that the information provided by the server is correct, the certificate is cryptographically signed by a certificate authority, or CA. If the client knows and trusts the CA, it can confirm that the certificate signature indeed comes from this entity, and with this the client can be certain that the server it connected to is legitimate.

openssl genrsa -aes256 -out key.key

openssl req -new -key key.key -out request.csr

openssl genrsa -aes256 -out ca.key
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

sh sign.sh request.csr

rename request.crt to certificate-signed.crt
