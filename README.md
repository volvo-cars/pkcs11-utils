# pkcs11gn

`pkcs11gn` is a dead-simple utility for signing and verifying files with PKCS#11 devices.

The tool is pronounced as "pee-kay-see-sign".

# Usage

This guide assumes that you have access to a configured [PIV-enabled YubiKey](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html).
In addition, you will need the [ykcs11 module](https://developers.yubico.com/yubico-piv-tool/YKCS11):
```shell
Linux: sudo apt install ykcs11
Mac: brew install yubico-piv-tool
Windows: https://developers.yubico.com/yubico-piv-tool/Releases
```

You need a to create a `~/.crypto11.json` such as [crypto11.config.yubikey](example/crypto11.config.yubikey)
with `Path`, `SlotNumber` and optionally `Pin` and X509 `CommonName` to identify the key you want to use. `CommonName`
is only required if your YubiKey has more than one cert loaded onto it.

The full set of configuration options is documented [here](https://pkg.go.dev/github.com/ThalesIgnite/crypto11#Config).
The only undocumented field is `CommonName` as it is only needed by this tool.

## Build
Compile the binary
`make pkcs11gn`

## Sign file

The following will sign `file.bin` with the private key on the PKCS#11 device.

```shell
pkcs11gn sign file.bin > file.bin.sig
```

## Verify signature with openssl (recommended)

Export the public key from the PKCS#11 device:

```shell
pkcs11gn pubkey >pubkey.pem
```

**NOTE**: Never keep the exported public key and signature files in the
same security domain (server/storage, etc.).

Hash (SHA256) your `file.bin` with openssl:

```shell
openssl dgst -sha256 -binary file.bin >file.bin.sha256
```

Verify with openssl that (all points):
* `file.bin.sig` contains a valid signature for the `file.bin.sha256` (indirectly `file.bin`)
* `file.bin.sig` was produced by the private key associated with `pubkey.pem`

```shell
openssl pkeyutl -verify -pubin -inkey pubkey.pem -sigfile file.bin.sig -in file.bin.sha256 \
    -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1
```

## Verify signature with pkcs11gn

The following will verify that (all points):
* `file.bin.sig` contains a valid signature for `file.bin`
* `file.bin.sig` was produced with the private key on the PKCS#11 device

```shell
pkcs11gn verify file.bin file.bin.sig
```

The advantage of this verification mode is that you don't have to maintain
a public key file in a secure way (integrity protection).

The main disadvantage is that you need to keep your PKCS#11 device connected and configured.
