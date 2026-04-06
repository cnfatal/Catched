# Network Probe

> Detects server-side components of injection frameworks by probing active TCP ports and Unix domain sockets, and by parsing kernel-exposed socket tables.

---

## Overview

Network Probe detection works by identifying the network endpoints that injection framework servers bind to for client communication. Injection tools such as Frida and Magisk operate on a client-server architecture: a privileged server process runs on the device and listens on well-known TCP ports or Unix domain sockets, while the client connects from a workstation or local process. By actively attempting TCP connections to known ports, performing protocol-level handshakes, and passively reading `/proc/net/tcp` and `/proc/net/unix` to enumerate all bound sockets, the detection logic can identify these server components even when the server process name has been disguised.

From a defender's perspective, network probing is valuable because a listening server must maintain a bound socket for the duration of its operation — this is a structural requirement that cannot be eliminated without breaking the server's functionality. While port numbers can be changed and socket names can be randomized, the default configurations provide a strong initial signal, and protocol-level handshakes provide confirmation that goes beyond simple port scanning.

---

## Injection Side

### How Attackers Use This Technique

1. **Deploy server component** — The attacker pushes a server binary (e.g., `frida-server`) to the device and runs it with root privileges.
2. **Bind to network endpoint** — The server binds a TCP socket to a loopback address (typically `127.0.0.1:27042` for the main control channel and `127.0.0.1:27043` for the script channel) or a Unix domain socket (e.g., Magisk daemon socket).
3. **Accept client connections** — The server listens for incoming connections from the injection client running on the analyst's workstation (via USB-forwarded TCP) or from local processes.
4. **Protocol communication** — The server implements a protocol for client commands. Frida uses D-Bus internally: the server expects a D-Bus AUTH handshake starting with a null byte followed by `AUTH\r\n`.
5. **Maintain persistent listener** — The server keeps the socket open for the entire instrumentation session, making it continuously detectable.

### Artifacts

| Artifact                           | Location              | Indicator                                                 |
| ---------------------------------- | --------------------- | --------------------------------------------------------- |
| TCP listening socket on port 27042 | `/proc/net/tcp`       | Local address field contains `69A2` (hex for 27042)       |
| TCP listening socket on port 27043 | `/proc/net/tcp`       | Local address field contains `69A3` (hex for 27043)       |
| D-Bus server response              | TCP connection data   | Response contains "REJECTED" or "OK" after AUTH handshake |
| Magisk Unix socket                 | `/proc/net/unix`      | Socket path contains "magisk"                             |
| frida-server process               | `/proc/<pid>/cmdline` | Process name matches frida-server or its variants         |

### Injection PoC _(optional)_

```pseudocode
// frida-server binds its control channel on startup
server_fd = socket(AF_INET, SOCK_STREAM, 0)
bind(server_fd, {127.0.0.1, 27042})
listen(server_fd, backlog=5)

// When client connects, perform D-Bus AUTH handshake
client_fd = accept(server_fd)
data = recv(client_fd)  // expects: "\x00AUTH\r\n"
if data starts with "\x00AUTH":
    send(client_fd, "REJECTED EXTERNAL DBUS_COOKIE_SHA1\r\n")
    // continue D-Bus session negotiation
```

### Evasion Techniques

| Evasion                 | Description                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| Custom port binding     | Run the server on a non-default port (e.g., `frida-server -l 0.0.0.0:31337`) to avoid default port scans      |
| Unix socket only        | Bind to a Unix domain socket with a randomized name instead of a TCP port, avoiding TCP-based probes entirely |
| Ephemeral binding       | Bind to port 0 (OS-assigned ephemeral port) so the port number is unpredictable                               |
| Namespace isolation     | Run the server in a separate network namespace to hide its sockets from the target process's `/proc/net/tcp`  |
| Socket name obfuscation | Use abstract Unix sockets with non-descriptive names to avoid string-based matching in `/proc/net/unix`       |

---

## Detection Side

### Mechanism

The invariant is that no legitimate application component should be listening on well-known injection framework ports (27042, 27043), should respond to D-Bus AUTH handshakes on arbitrary TCP connections, or should have Unix domain sockets with names associated with privilege escalation frameworks. A clean device has no process binding these endpoints; their presence indicates an active injection or privilege escalation server.

### Anti-Evasion Properties

| Property                    | Explanation                                                                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Protocol-level verification | D-Bus handshake confirms the server's identity regardless of port number or process name                                                                                        |
| Dual detection path         | Both active probing (connect) and passive scanning (/proc/net/tcp) are used — evading one still leaves the other                                                                |
| SVC bypass benefit          | Using SVC-based `socket`/`connect` and SVC-based `openat`/`read` for proc files bypasses hooked libc networking functions                                                       |
| Cross-protocol coverage     | Scanning both TCP and Unix sockets covers different server configurations                                                                                                       |
| Remaining bypass surface    | Custom ports with custom protocols defeat default port checks; network namespace isolation hides sockets from /proc/net/\*; kernel-level hooks can filter proc filesystem reads |

### Detection Strategy

1. **TCP port probe** — Create a TCP socket via SVC `socket(AF_INET, SOCK_STREAM, 0)`. Attempt `connect()` to `127.0.0.1:27042` and `127.0.0.1:27043` with a short timeout. If the connection succeeds, the port is open and a server is listening.
2. **D-Bus handshake verification** — On a successful TCP connection, send the D-Bus authentication initiation sequence: `\x00AUTH\r\n`. Read the response. If the response contains "REJECTED" or "OK", the server implements the D-Bus protocol, confirming it is a D-Bus-based injection server.
3. **Parse `/proc/net/tcp`** — Open and read `/proc/net/tcp` (via SVC). Each line after the header contains a `local_address` field in `hex_ip:hex_port` format. Search for port values `69A2` (27042) and `69A3` (27043) in the port portion. This catches servers bound to non-loopback addresses (e.g., `0.0.0.0`) that a loopback-only `connect()` would miss.
4. **Parse `/proc/net/unix`** — Open and read `/proc/net/unix` (via SVC). Each line contains an optional socket path in the last field. Search for paths containing the substring "magisk". A match indicates the presence of the Magisk daemon's communication socket.
5. **Correlate results** — An open port alone might be a false positive; combine with D-Bus handshake confirmation and `/proc/net/*` scan results for high-confidence detection.

### Detection PoC _(optional)_

```pseudocode
// Detection 1: Active TCP port probe
target_ports = [27042, 27043]
for port in target_ports:
    fd = svc_socket(AF_INET, SOCK_STREAM, 0)
    addr = sockaddr_in(AF_INET, port, 127.0.0.1)
    result = svc_connect(fd, addr, sizeof(addr))
    if result == 0:
        report("open injection server port", port)

        // Detection 2: D-Bus handshake verification
        svc_write(fd, "\x00AUTH\r\n", 7)
        response = svc_read(fd, buffer, 256)
        if "REJECTED" in response or "OK" in response:
            report("confirmed D-Bus server on port", port)

    svc_close(fd)

// Detection 3: Parse /proc/net/tcp for hex ports
fd = svc_openat(AT_FDCWD, "/proc/net/tcp", O_RDONLY, 0)
content = svc_read(fd, buffer, MAX_SIZE)
svc_close(fd)
for each line in content (skip header):
    local_port_hex = extract_port_field(line)
    if local_port_hex in ["69A2", "69A3"]:
        report("injection server port in /proc/net/tcp", local_port_hex)

// Detection 4: Parse /proc/net/unix for Magisk sockets
fd = svc_openat(AT_FDCWD, "/proc/net/unix", O_RDONLY, 0)
content = svc_read(fd, buffer, MAX_SIZE)
svc_close(fd)
for each line in content:
    if "magisk" in line:
        report("Magisk Unix socket detected", line)
```

### False Positive Risks

| Scenario                                                         | Mitigation                                                                                                   |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Legitimate application using port 27042/27043                    | Perform D-Bus handshake verification — legitimate services will not respond with D-Bus AUTH protocol         |
| Port reuse after server shutdown                                 | Probe actively with connect() rather than only checking /proc/net/tcp; a closed connection fails immediately |
| Custom ROM with diagnostic sockets containing "magisk" substring | Cross-reference with other detection signals (filesystem checks, property checks) before concluding          |
| Network probe blocked by SELinux policy                          | Detect the EACCES/EPERM error and log it separately — the inability to probe is itself informational         |

---

## References

- [Frida — default server port documentation](https://frida.re/docs/modes/)
- [D-Bus specification — AUTH protocol](https://dbus.freedesktop.org/doc/dbus-specification.html#auth-protocol)
- [Linux procfs — /proc/net/tcp format](https://www.kernel.org/doc/html/latest/networking/proc_net_tcp.html)
- [Linux procfs — /proc/net/unix format](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
- [Magisk — daemon architecture](https://topjohnwu.github.io/Magisk/details.html)
