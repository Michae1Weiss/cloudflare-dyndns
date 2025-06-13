## Important note
Consider using the [inadyn](https://github.com/troglobit/inadyn/tree/master). 
Works like a charm!
My rust ddns was just a try to handle this on my own. 

## Getting Started
1. Download `cloudflare-dyndns_0.1.0-1_amd64.deb` from releases
2. Install the package with `dpkg -i cloudflare-dyndns_0.1.0-1_amd64.deb`
3. Open `/etc/cloudflare-dyndns/config.toml` with text editor of your choise
4. Uncomment the variables and replace values with yours
5. Create a directory to hold your TLS files and cd into it `sudo mkdir -p /etc/cloudflare-dyndns/tls && cd /etc/cloudflare-dyndns/tls`
6. Generate a 2048-bit RSA private key `sudo openssl genrsa -out server.key 2048`
7. Generate a self-signed X.509 cert, valid for 365 days `sudo openssl req -new -x509  -key server.key -out server.crt -days 365 -subj "/CN=<your_domain>"`. Adjust `<your_domain>` to match your “record_name” (e.g. “example.com”).
8. Enable the service `systemctl enable cloudflare-dyndns.service`
9. Start the service  `systemctl start cloudflare-dyndns.service`
10. Go to your router and enable the DynDNS setting
11. In the `Update-URL` field instert `https://192.168.1.1:8888/update?myip=<ip6addr>` for IPv6 or `https://192.168.1.1:8888/update?myip=<ipaddr>` for IPv4
12. Enter your domain name in the `domain name` input field and save the changes.
13. **That's it**! Now router should send the request to the server with new IP address.

## How to test if DynDNS works?
```
curl -k "https://<ip>:8888/update"
```
Replace `<ip>` with the local IPv4 address of your server.
It should return the message `Missing myip parameter`
