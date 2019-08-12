# Docker OpenSSH Server debuging

This projet helps if you need to debug the key exchange on a OpenSSH Server.

## Usage

```sh
docker build . -t ssh_test && docker run -d -p 2222:22 --name ssh_test ssh_test && docker logs -f ssh_test
```

## Example Output

```
debug1: Local version string SSH-2.0-OpenSSH_8.0
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
debug1: match: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3 pat OpenSSH_7.0*,OpenSSH_7.1*,OpenSSH_7.2*,OpenSSH_7.3*,OpenSSH_7.4*,OpenSSH_7.5*,OpenSSH_7.6*,OpenSSH_7.7* compat 0x04000002
debug2: fd 4 setting O_NONBLOCK
debug3: ssh_sandbox_init: preparing seccomp filter sandbox
debug2: Network child is on pid 49
debug3: preauth child monitor started
debug3: privsep user:group 999:999 [preauth]
debug1: permanently_set_uid: 999/999 [preauth]
debug3: ssh_sandbox_child: setting PR_SET_NO_NEW_PRIVS [preauth]
debug3: ssh_sandbox_child: attaching seccomp filter program [preauth]
debug1: list_hostkey_types: rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519 [preauth]
debug3: send packet: type 20 [preauth]
debug1: SSH2_MSG_KEXINIT sent [preauth]
debug3: receive packet: type 20 [preauth]
debug1: SSH2_MSG_KEXINIT received [preauth]
debug2: local server KEXINIT proposal [preauth]
debug2: KEX algorithms: curve25519-sha256 [preauth]
debug2: host key algorithms: rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519 [preauth]
debug2: ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com [preauth]
debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com [preauth]
debug2: MACs ctos: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1 [preauth]
debug2: MACs stoc: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1 [preauth]
debug2: compression ctos: none,zlib@openssh.com [preauth]
debug2: compression stoc: none,zlib@openssh.com [preauth]
debug2: languages ctos:  [preauth]
debug2: languages stoc:  [preauth]
debug2: first_kex_follows 0  [preauth]
debug2: reserved 0  [preauth]
debug2: peer client KEXINIT proposal [preauth]
debug2: KEX algorithms: curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c [preauth]
debug2: host key algorithms: ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa [preauth]
debug2: ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com [preauth]
debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com [preauth]
debug2: MACs ctos: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1 [preauth]
debug2: MACs stoc: umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1 [preauth]
debug2: compression ctos: none,zlib@openssh.com,zlib [preauth]
debug2: compression stoc: none,zlib@openssh.com,zlib [preauth]
debug2: languages ctos:  [preauth]
debug2: languages stoc:  [preauth]
debug2: first_kex_follows 0  [preauth]
debug2: reserved 0  [preauth]
debug1: kex: algorithm: curve25519-sha256 [preauth]
debug1: kex: host key algorithm: ecdsa-sha2-nistp256 [preauth]
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none [preauth]
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none [preauth]
debug1: expecting SSH2_MSG_KEX_ECDH_INIT [preauth]
client public key 25519:
0000: a4 91 debug3: receive packet: type 30 [preauth]
d9 e1 47 4d 39 9c 35 01 76 07 60 df 36 3d  ....GM9.5.v.`.6=
0016: 1b b8 75 85 9c 2a 92 ac 0e 8f 6c 37 e3 e1 11 72  ..u..*....l7...r
shared secret
0000: 0d 55 a3 14 a3 b7 4d 17 0d a0 29 f8 57 4c bd 8c  .U....M...).WL..
0016: 68 2b 62 b2 40 f4 73 af b4 5a fc c9 8a 78 57 11  h+b.@.s..Z...xW.
server public key 25519:
0000: dc c5 e1 11 56 97 3d 7a 0f 89 eb 00 7c 30 1b 0a  ....V.=z....|0..
0016: 76 35 54 b6 98 79 93 e4 41 99 40 2e ec 92 92 24  v5T..y..A.@....$
encoded shared secret:
0000: 00 00 00 20 0d 55 a3 14 a3 b7 4d 17 0d a0 29 f8  ... .U....M...).
0016: 57 4c bd 8c 68 2b 62 b2 40 f4 73 af b4 5a fc c9  WL..h+b.@.s..Z..
0032: 8a 78 57 11                                      .xW.
debug3: mm_sshkey_sign entering [preauth]
debug3: mm_request_send entering: type 6 [preauth]
debug3: mm_request_receive entering
debug3: monitor_read: checking request 6
debug3: mm_answer_sign
debug3: mm_answer_sign: hostkey proof signature 0x556ff980e8d0(101)
debug3: mm_request_send entering: type 7
debug2: monitor_read: 6 used once, disabling now
debug3: mm_sshkey_sign: waiting for MONITOR_ANS_SIGN [preauth]
debug3: mm_request_receive_expect entering: type 7 [preauth]
debug3: mm_request_receive entering [preauth]
debug3: send packet: type 31 [preauth]
debug3: send packet: type 21 [preauth]
debug2: set_newkeys: mode 1 [preauth]
debug1: rekey out after 134217728 blocks [preauth]
debug1: SSH2_MSG_NEWKEYS sent [preauth]
debug1: expecting SSH2_MSG_NEWKEYS [preauth]
debug3: send packet: type 7 [preauth]
debug3: receive packet: type 21 [preauth]
debug1: SSH2_MSG_NEWKEYS received [preauth]
debug2: set_newkeys: mode 0 [preauth]
debug1: rekey in after 134217728 blocks [preauth]
debug1: KEX done [preauth]
debug3: receive packet: type 5 [preauth]
debug3: send packet: type 6 [preauth]
debug3: receive packet: type 50 [preauth]
debug1: userauth-request for user florian service ssh-connection method none [preauth]
debug1: attempt 0 failures 0 [preauth]
debug3: mm_getpwnamallow entering [preauth]
debug3: mm_request_send entering: type 8 [preauth]
debug3: mm_getpwnamallow: waiting for MONITOR_ANS_PWNAM [preauth]
debug3: mm_request_receive_expect entering: type 9 [preauth]
debug3: mm_request_receive entering [preauth]
debug3: mm_request_receive entering
```

The Dockerfile build OpenSSH-Server with the option `DEBUG_KEXECDH` that allow to display the secret inside the key exchange.

```
client public key 25519:
0000: a4 91 d9 e1 47 4d 39 9c 35 01 76 07 60 df 36 3d  ....GM9.5.v.`.6=
0016: 1b b8 75 85 9c 2a 92 ac 0e 8f 6c 37 e3 e1 11 72  ..u..*....l7...r
shared secret
0000: 0d 55 a3 14 a3 b7 4d 17 0d a0 29 f8 57 4c bd 8c  .U....M...).WL..
0016: 68 2b 62 b2 40 f4 73 af b4 5a fc c9 8a 78 57 11  h+b.@.s..Z...xW.
server public key 25519:
0000: dc c5 e1 11 56 97 3d 7a 0f 89 eb 00 7c 30 1b 0a  ....V.=z....|0..
0016: 76 35 54 b6 98 79 93 e4 41 99 40 2e ec 92 92 24  v5T..y..A.@....$
encoded shared secret:
0000: 00 00 00 20 0d 55 a3 14 a3 b7 4d 17 0d a0 29 f8  ... .U....M...).
0016: 57 4c bd 8c 68 2b 62 b2 40 f4 73 af b4 5a fc c9  WL..h+b.@.s..Z..
0032: 8a 78 57 11                                      .xW.
```

## Security disclamer

Please use only this projet for debuging purpose. The docker image is build with insecure parameter (`DEBUG_KEXECDH`).

