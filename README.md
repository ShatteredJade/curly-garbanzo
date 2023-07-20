# curly-garbanzo

A TCP oriented chatroom that allows users to create accounts and for administrators to execute basic commands (i.e. kick, ban)

## Features

- All account data is stored within a database, with passwords being hashed for extra security.
- The chatroom is one server in which all users connect to, allowing for them to message everyone at once
- Users may be manually promoted into admins, by which they may execute certain commands

## Instructions

Bcrypt is required for password hashing.

You can install it manually via

    pip install bcrypt

or by using the requirements.txt

    pip install -r requirements.txt

The default administrator account login is

Username: Archaon (case sensitive)

Password: pass
