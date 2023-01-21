# Linux Privilege Escalation Captstone

Start SSH:
User: leonard
Pass: Penny123

Enumerate

/proc/version

gives us Linux Kernel 3.10.0

Exploit CVE 2017-1000253:
    I couldn't get this to work succesfully though I compiled and ran it.
First I started a http.Server on my computer and uploaded the exploit and the rootshell.c file
Then use gcc to compile rootshell.c on the remote system
Then use xxd to make the header rootshell.h
Then compile the exploit
Chmod +x  exploit
and run
No dice: died in main 259.

run linpeas...

base64 vulnerability:
use base64 to read shadow file.
Copy shadow of missy and passwd entry of missy
unshadow on local machine
john the ripper on local machine with rockyou.txt
password is ........
get flag 1:
THM-42828719920544


Mi ssy can run /usr/bin/find as sudo with no password (does not work with PATH find )

so from GTFO bin we modify the sudo find command to:

sudo /usr/bin/find . -exec /bin/sh \; -quit 

And voila:

sh-4.2$ sudo /usr/bin/find . -exec /bin/sh \; -quit
sh-4.2# whoami
root
sh-4.2# find / -name flag*.txt 2>/dev/null
/home/missy/Documents/flag1.txt
/home/rootflag/flag2.txt
sh-4.2# cat /home/rootflag/flag2.txt
THM-***************168824782390238***************
