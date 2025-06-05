## Getting Started
1. Download `cloudflare-dyndns_0.1.0-1_amd64.deb` from releases
2. Install the package with `dpkg -i cloudflare-dyndns_0.1.0-1_amd64.deb`
3. Open `/etc/cloudflare-dyndns/config.toml` with text editor of your choise
4. Uncomment the variables and replace values with yours
5. Enable the service `systemctl enable cloudflare-dyndns.service`
6. Start the service  `systemctl start cloudflare-dyndns.service`
7. Go to your router and enable the DynDNS setting
8. In the `Update-URL` field instert `http://192.168.1.1:8888/update?myip=<ip6addr>` for IPv6 or `http://192.168.1.1:8888/update?myip=<ipaddr>` for IPv4
9. Enter your domain name in the `domain name` input field and save the changes.
10. **That's it**! Now router should send the request to the server with new IP address.

## How to test if DynDNS works?
```
curl "http://<ip>:8888/update"
```
Replace `<ip>` with the local IPv4 address of your server.
It should return the message `Missing myip parameter`
