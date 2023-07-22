# curly-garbanzo

A TCP oriented chatroom that allows users to create accounts and for administrators to execute basic commands (i.e. kick, ban)

## Features

- Passwords hashed using Bcrypt
- All account data is stored within a database
- The chatroom is one server in which all users connect to, allowing for them to message everyone at once
- Users may be manually promoted into admins, by which they may execute certain commands

## Instructions

Install required modules using requirements.txt

    pip install -r requirements.txt


The default administrator account login is

Username: Archaon

Password: pass

## Examples

Logging in, using the default admin account as an example.

```
Please enter a username: Archaon
Please enter a password: pass
INFO:__main__:Successfully logged in as Archaon
```

Chatting between users, from Archaon's perspective.

```
Jade: Hello!
Hihi~
Archaon: Hihi~
How are you today?
Archaon: How are you today?
Jade: I'm fine, and you?
well :)
Archaon: well :)
```

Kicking and banning from an admin's perspective.

```
!kick jade
Archaon has kicked user Jade
Jade: I'm back!
!ban jade
Archaon has banned user Jade
```

Kicking and banning from a user's perspective.

```
You have been kicked by admin Archaon
ERROR:__main__:Connection lost!
```

```
Please enter a username: jade
Please enter a password: pass
INFO:__main__:Successfully logged in as Jade
I'm back!
Jade: I'm back!
You have been banned by admin Archaon
ERROR:__main__:Connection lost!
```

```
Please enter a username: jade
Please enter a password: pass
INFO:__main__:Login failed: User has been banned
```

Disconnect command.

```
Please enter a username: example
Please enter a password: user
INFO:__main__:Successfully logged in as Example
!disconnect
INFO:__main__:Disconnecting...
```

Example server logs.

```
INFO:__main__:Database could not be created as it already exists
INFO:__main__:Server is listening...
INFO:__main__:Connected with 127.0.0.1:51481
INFO:__main__:Attempting login with 127.0.0.1:51481...
INFO:__main__:Requesting username from 127.0.0.1:51481
INFO:__main__:Requesting password from 127.0.0.1:51481
INFO:__main__:Checking if Archaon exists in database
INFO:__main__:Checking password for requested login for Archaon
INFO:__main__:Checking Archaon's role
INFO:__main__:Accepted login with 127.0.0.1:51481 as Archaon
INFO:__main__:Connected with 127.0.0.1:51499
INFO:__main__:Attempting login with 127.0.0.1:51499...
INFO:__main__:Requesting username from 127.0.0.1:51499
INFO:__main__:Requesting password from 127.0.0.1:51499
INFO:__main__:Checking if Jim exists in database
INFO:__main__:Attempting to create account Jim
INFO:__main__:Account Jim successfully created
INFO:__main__:Accepted login with 127.0.0.1:51499 as Jim
INFO:__main__:Checking Archaon's role
INFO:__main__:Archaon requested to kick Jim
INFO:__main__:Attempting to kick Jim by admin Archaon
INFO:__main__:Archaon has kicked user Jim
INFO:__main__:Closed connection with Jim (127.0.0.1:51499)
```
