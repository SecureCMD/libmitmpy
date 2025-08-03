1. Use an existing library:
Don't reinvent the TLS wheel. Use something like mitmproxy or [pydivert + cryptography] if you're feeling spicy.
But since you’re writing your own proxy, you might want a more DIY approach. Here’s a minimal viable way:

2. Create a CA cert
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.pem
Then convert that to a .crt and install it as trusted in your system or certifi.
3. When a CONNECT comes in:
Parse the domain.
Generate a fake cert for that domain, signed with your CA.
Respond with "200 Connection Established".
Wrap the client socket in ssl.wrap_socket using your generated cert.
Make a new TLS connection to the real server.
Now you can sit in the middle and decrypt traffic.
4. Use libs like ssl, cryptography, and http.client to help.