# File Inclusion

Exploiting insecure coding where file systems may be traversed or contents of files read through web apps.

/lab1.php?file=/etc/passwd

just add the query ? file = and the file you want to read.

flag 2 careful, this is in *lab 2* I wasted a few minutes (honestly hours) searching the output of error messages in lab 1. Go to lab 2 and stick in a file that doesn't exist and you will find the folder that is being included...it's 'includes'. Don't be a Tom. 

Lab 3: (page 2)
Here we know we have to traverse back 4 steps from /var/www/html/includes but the app is adding '.php' to whatever file we give it so it throws an error if we just put:
http://10.10.108.216/lab3.php?file=../../../../etc/passwd

Adding a 'null byte' '%00' terminates the string and makes the app disregard anything after. *This is fixed in newer versions of php*

http://10.10.108.216/lab3.php?file=../../../../etc/passwd%00
gets us the read-out of etc/passwd

