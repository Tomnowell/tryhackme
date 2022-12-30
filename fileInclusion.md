# File Inclusion

Exploiting insecure coding where file systems may be traversed or contents of files read through web apps.

/lab1.php?file=/etc/passwd

just add the query ? file = and the file you want to read.

flag 2 careful, this is in *lab 2* I wasted a few minutes (honestly hours) searching the output of error messages in lab 1. Go to lab 2 and stick in a file that doesn't exist and you will find the folder that is being included...it's 'includes'. Don't be a Tom. 

