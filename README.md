## Guide

Portal is a TCP Tunnel. It only support IPv4 now.

It helps that a service on Internet to fetch sets of data from an Intranet service. This is its common usage case. Besides that, it can help to build up a tunnel across many servers (whether or not on Internet) for decreasing network delay.

* Environment
* Install
* Configure
* Run

## Environment

Portal is tested on Ubuntu 16.04 x86_64. It is written in C, so we need a C compiler (most Linux distribution already installed).

Portal only can working on Linux now, so you may need a Linux server to install it.

## Install

Installation is very easy, just one command.

```
sudo make
```

It will get the newest version of Melon and compile it and Portal.

The target execute file will be built in current directory (portal/).

## Configure

### Where is configuration file

There are five configuration files under directory `confs`.

### Configuration format

Portal is built up based on Melon (Melon is a framework library written in C), so its configuration file will derived from Melon's.

```
/*
 * log level, it has 5 levels, from lowest priority to highest, they are,
 * none, report, debug, warn and error.
 * This configuration Item means that logger records that messages those only higher or
 * equal to level 'none'.
 */
log_level "none";
/*
 * Process's uid in runtime.
 */
user "root";
daemon off;
/*
 * core file size if it generated unfortunately :-(.
 */
core_file_size "unlimited";
/*
 * The maximum of opened file descriptors.
 */
max_nofile 1024;
/*
 * Number of worker process.
 */
worker_proc 1;/*must be 1*/
thread_mode off; /*ignore this*/
framework on;/*ignore this*/
/*
 * Log file path.
 * You can modify this path and reload process in runtime.
 * For more detail, please see Melon's developer guide.
 */
log_path "/usr/local/melon/logs/melon.log";

...(ignore some useless items)

/*
 * All portal's configurations.
 */
portal {
    certify_token "abcdfg"; /*rc4 secret key, client's and server's must be identical.*/
    tunnel_number 100; /*only used on Tunnel client*/
    outerAddr "127.0.0.1:9999"; /*the address for accessing all other service*/
    innerAddr "0.0.0.0:1234";/*the address for accessing client or server*/
    role "server";/* "server" or "client" */
    /*
     * timeout:
     * -1 means never timeout.
     * < -1 will raise a fault while starting up.
     */
    inner_timeout 3000;/*ms -- ping timeout in Tunnel, connection timeour in Proxy.*/
    outer_timeout 3000;/*ms -- connection timeout (not used on Tunnel client)*/
    retry_timeout 3000;/*ms -- re-connect timeout (only used on Tunnel client)*/
    /*
     * mode only used on Tunnel.
     * There are two cases.
     * 1. A client connects to the server and it will send TCP data at first.
     * 2. A client connects to the server and wait for receiving data from server.
     * 1 -- positive.
     * 2 -- negative.
     * For mysql, it should be set negative.
     * This configuration item only works on client.
     */
    mode "positive";/* "positive" or "negative" */
    as "proxy";/*proxy, tunnel or broadcaster
                 indicates Portal will be used as a proxy, tunnel or broadcaster*/
}
```

## Run

There are five modes of Portal manipulated by configuration file.

- tunnel server

- tunnel client

- proxy server

- proxy client

- broadcaster

You can find these configuration templates in directory `confs`.

If we execute

```
./portal
```

Program will try to look for the configuration file in Melon's (core framework) installation directory.

So, we can designate the configuration file path through the `-c` parameter.

```
./portal -c /.../path/to/conf
```
