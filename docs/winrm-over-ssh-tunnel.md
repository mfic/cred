# WinRM over an SSH tunnel, without NTLM

`Get-CredCredential` hands you a `PSCredential` and the obvious next move is
`New-PSSession -Credential $cred`. On a **non-domain-joined admin workstation
reaching a Windows estate through an SSH tunnel**, that works — right up to the
day the account is hardened, and then it fails in a way that names none of its
causes.

This note is the method and the traps. It is estate-agnostic: nothing here
depends on which customer you are working for. It was verified on one
configuration, stated at the end, and claims that come from running the thing
say so.

## The easy path, and why it expires

A port forward is addressed as `localhost`, and **`localhost` has no SPN**. So
`Negotiate` cannot use Kerberos and falls back to NTLM:

```powershell
# ssh -N -L 45985:10.0.0.30:5985 jumphost
$cred = Get-CredCredential acme/adm.alice
$s = New-PSSession -ComputerName localhost -Port 45985 -Credential $cred -Authentication Negotiate
```

Windows permits that fallback only because the client's `TrustedHosts` is
permissive, which is its own problem. The method is simple, needs no setup, and
is what most tunnelling write-ups show.

**It stops working the moment NTLM does.** The common trigger is the account
joining **`Protected Users`**, which forbids NTLM outright — but anything that
restricts NTLM (an `LmCompatibilityLevel` raise, `RestrictSendingNTLMTraffic`,
an authentication policy) has the same effect. If your estate is moving toward
tiered administration, this *will* happen, and it will happen to the account all
your automation uses.

## The method that survives it

Four things, and the third is the one nobody expects.

### 1. Tell a workgroup client where the realm is

Elevated, once, then **reboot** — the LSA reads this at boot:

```powershell
ksetup /addkdc EXAMPLE.COM dc1.example.com
ksetup /addkpasswd EXAMPLE.COM dc1.example.com
ksetup /addhosttorealmmap .example.com EXAMPLE.COM
```

`ksetup` with no arguments prints the realm and KDC but **never displays
host-to-realm maps** — their absence from the output is not failure. Read them
at `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm`.

**`ksetup /setdomain` is not required.** It changes the machine's default logon
realm and was shown unnecessary; leave it alone.

### 2. Make the target's real name resolve to the forward

Kerberos derives the SPN from the **connection string**, so the name you connect
to must be the target's actual FQDN. Point it at the loopback in `hosts`:

```
127.0.0.1 app01.example.com
127.0.0.1 dc1.example.com
```

**The port is irrelevant.** The SPN excludes it by default, so a forward on
45985 still yields `HTTP/app01.example.com`. You do **not** need to free 5985
locally — which matters, because the local WinRM service may hold it
exclusively in http.sys even with no listener configured.

### 3. Bridge Kerberos UDP onto the TCP tunnel

**This is what makes or breaks it.** The Windows Kerberos client sends AS-REQ
and TGS-REQ as **raw UDP datagrams**. `ssh -L` forwards only TCP. So the
datagrams leave the client and hit nothing: no error, no retry onto TCP, and
**no entry in any log on either side**.

Two things that look like fixes and are not:

- **`MaxPacketSize = 1`** (`…\Lsa\Kerberos\Parameters`) is widely cited as
  forcing Kerberos onto TCP. Set, with a reboot, it **did not** force TCP for
  the initial AS-REQ.
- **MIT `krb5.conf` can name a KDC with an explicit port and a `tcp/` prefix.**
  Most guidance on this subject is written for MIT Kerberos and does not
  transfer: Windows has no `krb5.conf`, and `ksetup` cannot take a port at all.

So bridge it. Kerberos over TCP (RFC 4120 §7.2.2) prefixes each message with its
length in **four octets, network byte order**; over UDP the message is raw. This
is therefore a protocol translation, not a relay:

1. Receive a UDP datagram on `127.0.0.1:88`, remembering the sender's port.
2. Open TCP to the forwarded KDC port.
3. Write the 4-octet big-endian length, then the datagram.
4. Read 4 octets of length, then exactly that many bytes.
5. Send those bytes back by UDP to the sender's port.

On Linux or macOS, `socat` does this and the pattern is long-established in
research computing (`dmwm/ssh-fu`'s `kdc-tunnel`). **`socat` has no native
Windows build**, so on Windows it is ~50 lines of `System.Net.Sockets` — the
five steps above, in a loop, with a `TcpClient` per datagram. Keep that script
in the estate repo it serves rather than sharing one across repos: it is short
enough that a copy costs less than a cross-repo dependency.

A healthy run logs the whole exchange, and the ASN.1 tags are worth recognising:

| Tag | Message |
| --- | ------- |
| `0x6a` | AS-REQ (what the client emits, ~161 bytes) |
| `0x7e` | KRB-ERROR — normally *preauth required*, and expected |
| `0x6b` | AS-REP — the TGT was issued |
| `0x6d` | TGS-REP — the service ticket was issued |

### 4. Forward the KDC ports as well as WinRM

```bash
ssh -N -L 5985:10.0.0.49:5985 -L 88:10.0.0.10:88 \
       -L 464:10.0.0.10:464  -L 389:10.0.0.10:389 jumphost
```

Then connect **by name**, with no `localhost` anywhere:

```powershell
$cred = Get-CredCredential acme/adm.alice
$s = New-PSSession -ComputerName app01.example.com -Credential $cred -Authentication Kerberos
```

## Diagnosing it

**`0x80090311` (`SEC_E_NO_AUTHENTICATING_AUTHORITY`, *"your domain is not
available"*) is the only error you will see, for every distinct cause.** Do not
try to read it; work by elimination.

| Check | What it tells you |
| ----- | ----------------- |
| Is the **bridge** running? | By far the most common cause. Without it the client emits UDP into nothing. |
| `ssh -v` shows **no channel on 88** | **Expected even when healthy** — the bridge opens that TCP connection, not the client. Do not read it as "the client never tried". |
| A UDP listener on `127.0.0.1:88` sees ~161-byte datagrams starting `6a 81 …` | The client **is** trying. Those are AS-REQs; the problem is downstream. |
| A raw probe to the forwarded KDC port returns bytes | The forward reaches a live KDC. A bare TCP **connect** proves nothing: `ssh` accepts on its local listener before attempting the remote hop, so a successful connect is consistent with a dead far side. |
| Client clock within 5 minutes of the KDC | Kerberos fails outside it and never says why. |
| Credential form | Not a cause. `REALM\user`, `user@REALM`, `NETBIOS\user` and `user@realm` all behave identically here. |

**Microsoft's WinRM documentation states that both the client and the server
must be joined to a domain for Kerberos.** That is **not true of this path** — a
workgroup client authenticates successfully with the four steps above. Expect to
be told otherwise.

## One consequence worth designing around

**The target's `4624` carries the jump host's address, not the workstation's.**
Every tunnelled administrative action looks identical regardless of who
performed it or from where, so tunnelled access is **unattributable from the
target's event log alone**. Correlating with the jump host's own `sshd` log is
the only route to attribution. If you are building audit evidence that an
administrative boundary held, this matters more than it first appears.

## Verified configuration

Run against a live `Windows2016Domain` forest on **01.10.2026**, from a
workstation that is **not domain-joined and has no RSAT**, over an SSH tunnel
with the VPN down. Evidence: a type-3 logon on the target with
`AuthenticationPackageName = Kerberos`, `LmPackageName = -`, and **zero `4776`**
NTLM-validation events — including for an account that was a member of
`Protected Users` at the time, which is the case the whole method exists for.

Everything above about `MaxPacketSize`, the credential forms, the silent UDP
loss and the `0x80090311` ambiguity is from running it, not from documentation.
