# DNS spoof

This Python script performs an ARP to DNS spoofing attack, enabling the interception of network traffic and redirection of DNS requests for example.com to a specified local IP address. By sending forged ARP messages throughout the network, it associates the attacker's MAC address with that of a legitimate device, such as a router. The script also listens for UDP packets to modify their content, effectively allowing it to alter DNS responses.

### install

```bash
git clone https://github.com/savasick/dnsspoof.git
cd dnsspoof
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### run

```bash
sudo python3 dnsspoof.py 192.168.5.187
```

#### to run web server at 80 port for web page

```bash
docker build -t website . && docker run --rm -p 80:80 website
```

#### to check DNSspoofing works use
```
ping example.com
```