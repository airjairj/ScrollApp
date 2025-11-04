# PC Server

This project implements a TCP server that listens for client connections and processes commands to simulate mouse wheel scrolling.

## Files

- **src/pc_server.c**: Contains the implementation of the TCP server, including functions for handling client connections, sending mouse events, and managing socket communication.
- **Makefile**: Build instructions for compiling the project using `make`. It specifies the compiler and the necessary flags and libraries to link against.
- **build.bat**: A batch script for building the project on Windows, compiling the `pc_server.c` file using either MSVC or MinGW.
- **.gitignore**: Specifies files and directories that should be ignored by Git version control.

## Compilation Instructions

### On Windows

To compile the project on Windows, you can use the provided `build.bat` script. Simply run the script in the command prompt:

```
build.bat
```

Alternatively, you can compile the project manually using the following commands:

For MSVC:
```
cl src/pc_server.c /link Ws2_32.lib
```

For MinGW:
```
gcc src/pc_server.c -o pc_server.exe -lws2_32
```

### Running the Server

After compiling, you can run the server executable. The server will start listening for client connections on the specified port (default is 55005). 

Make sure to connect a client to the server to send commands for mouse wheel scrolling or to disconnect.