----------------

## Guide
----------------
Portal is a TCP Tunnel. It only support IPv4 now.

It helps that a service on Internet to fetch sets of data from an Intranet service. This is its common usage case. Besides that, it can help to build up a tunnel across many servers (whether or not on Internet) for decreasing network delay.

* Environment
* Install
* Configure
* Run

## Environment
----------------

Portal is tested on Ubuntu 16.04 x86_64. It is written in C, so we need a C compiler (most Linux distribution already installed).

Portal only can working on Linux now, so you may need a Linux server to install it.

## Install
----------------

Installation is very easy, just one command.

```
sudo make
```

It will get the newest version of Melon and compile it and Portal.

The target execute file will be built in current directory (portal/).

## Configure

----------------

### Where is configuration file

In Portal directory, there are two configuration files, *melon.conf.srv* and *melon.conf.cli*.

*melon.conf.srv* is server's configuration file and *melon.conf.cli* is client's.

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

----------------

How to run Portal.

In its configuration file, we can see some configuration items can modify system limitations. Which means, we have to start it up with *root*.

After initialization, the uid of the process will be modified to the user that assigned by configuration item *user*.

After all preparations, you can run our script file to start up.

```
sudo ./startup type
```

*type* has 5 values can be chosen:

​	*proxy_server* — this type will indicate portal to be started up as a proxy server

​	*proxy_client* — this type will indicate portal to be started up as a proxy client

​	*tunnel_server* — this type will indicate portal to be started up as a tunnel server

​	*tunnel_client* — this type will indicate portal to be started up as a tunnel client

​	*broadcaster* — this type will indicate portal to be started up as a broadcaster