# Client - Server 🖥️💻

## Implementation of a Client-Server architecture.
Communication via sockets and using TCP and UDP protocols.

Client coded in ANSI C. Server coded in Python.

# How to use it ❓

## 1. Config files ⚙️

There's two config files, one for the client ( _client.cfg_ ) and one for the server ( _server.cfg_ ).

In the _client.cfg_ file there's five options that can be configured:
  - __Id__ : It is the client identification. Used by the server for identifying multiple clients and for authing purposes.
  - __Elements__ : It simulates some sensors connected to the client. (Theorically client simulates a industry machine console)
  - __Local-TCP__ : The TCP port where the client is going to listen to.
  - __Server__ : The server ip/hostname address. If you are running it in your own pc, leave it to _localhost_.
  - __Server-UDP__ : The UDP port where the client is going to send register information to the server[^1].


On the other side _literally xD_, in the _server.cfg_ file there's only three options:
  - __Id__ : The server identification.
  - __UDP-Port__ : The UDP port where the server is listening for new clent registration[^1].
  - __TCP-Port__ : The TCP port where the server is going to accept incoming connections.

Additionally, there's one more file ( _bbdd_dev.dat_ ) from the server side, where you can define which client's id are authorized to connect to the server.

Please, make sure to respect the length of every config option cause if not, may occur some fatal crashes...

## 2. Run it ⏯️!

When you have it all configured, first of all, you have to compile the _client.c_.
Just open the folder with a terminal, and execute `make all`.

When you have it compiled, just execute the _server.py_ and, if you are in the same computer, open another terminal and execute the _client_ file recently compiled.
And _voilà_, you are running a client-server arch in your computer!

## 3. Execution options 🪛

There's some optional parameters for running the programs with some personalization.

The client execution options look like that: `$ .\client <-d> <-c {filename.cfg}>`
  - With the `-d` option you execute the client in __debug mode__. So you are going to see some additional information of what is happening in the background.
  - With the `-c {filename.cfg}` option you are able to run an specific client file config. With that, you can run multiple client simultaneously.


The server execution options can be like that: `$ .\server.py <-d> <-c {filename.cfg}> <-u {filename.dat}>`
  - The new option is the `-u {filename.dat}` where you can define which datebase file you want to run on the server. With different users if you want...

## 4. Terminal commands ⌨️

When the server is running and one client is connected to it, you can run different commands using the default input through the terminal.

In the client, you can execute:
  - `stat` : Shows the client's elements id and its values.
  - `set <element_id> <new_value>` : Sets an element value.
  - `send <element_id>` : Sends and element value to the server.
  - `quit` : Closes the client.

And in the server:
  - `set <client_id> <element_id> <value>` : Sets a value to a client element.
  - `get <client_id> <element_id>` : Gets the value from a client element.
  - `list` : Lists all the clients with its states, communcation id, ip addresses and elements id.
  - `quit` : Exits the server closing all buffers, sockets, etc.


There's some error handling implemented, so if you put an incorrect command, or a correct one with invalid syntax, the program will show you.


# Have fun with it! ❇️🌠

PD: This implementation took me about 2 months of hard work and lost sleep hours, so please, appreciate it! 😮‍💨

[^1]: Make sure that the UDP port is the same in both config files.
