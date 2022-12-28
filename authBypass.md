# authorization bypassing

We're using ffuf (fuzz faster you fool) To enumerate usernames through the signupform

The tool sends a http POST and compares the response if the reply contains 'username already exists' that is a valid user.

## Usernames

admin
robert
simon
steve
