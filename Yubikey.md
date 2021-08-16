This is a guide to using [YubiKey](https://www.yubico.com/products/yubikey-hardware/) as a [SmartCard](https://security.stackexchange.com/questions/38924/how-does-storing-gpg-ssh-private-keys-on-smart-cards-compare-to-plain-usb-drives) for storing GPG encryption, signing and authentication keys, which can also be used for SSH. Many of the principles in this document are applicable to other smart card devices.

Keys stored on YubiKey are [non-exportable](https://support.yubico.com/support/solutions/articles/15000010242-can-i-duplicate-or-back-up-a-yubikey-) (as opposed to file-based keys that are stored on disk) and are convenient for everyday use. Instead of having to remember and enter passphrases to unlock SSH/GPG keys, YubiKey needs only a physical touch after being unlocked with a PIN. All signing and encryption operations happen on the card, rather than in OS memory.

- [Purchase](#purchase)
- [Prepare environment](#prepare-environment)
- [Entropy](#entropy)
  - [YubiKey](#yubikey)
- [Creating keys](#creating-keys)
  - [Temporary working directory](#temporary-working-directory)
  - [Harden configuration](#harden-configuration)
- [Master key](#master-key)
- [Sign with existing key](#sign-with-existing-key)
- [Sub-keys](#sub-keys)
  - [Signing](#signing)
  - [Encryption](#encryption)
  - [Authentication](#authentication)
  - [Add extra identities](#add-extra-identities)
- [Verify](#verify)
- [Export secret keys](#export-secret-keys)
- [Revocation certificate](#revocation-certificate)
- [Backup](#backup)
- [Export public keys](#export-public-keys)
- [Configure Smartcard](#configure-smartcard)
  - [Change PIN](#change-pin)
  - [Set information](#set-information)
- [Transfer keys](#transfer-keys)
  - [Signing](#signing-1)
  - [Encryption](#encryption-1)
  - [Authentication](#authentication-1)
- [Verify card](#verify-card)
- [Cleanup](#cleanup)
- [Using keys](#using-keys)
- [Rotating keys](#rotating-keys)
- [SSH](#ssh)
  - [Replace agents](#replace-agents)
  - [Copy public key](#copy-public-key)
  - [(Optional) Save public key for identity file configuration](#optional-save-public-key-for-identity-file-configuration)
  - [Connect with public key authentication](#connect-with-public-key-authentication)
  - [Import SSH keys](#import-ssh-keys)
  - [Remote Machines (SSH Agent Forwarding)](#remote-machines-ssh-agent-forwarding)
    - [Use ssh-agent](#use-ssh-agent)
    - [Use S.gpg-agent.ssh](#use-sgpg-agentssh)
    - [Chained SSH Agent Forwarding](#chained-ssh-agent-forwarding)
  - [GitHub](#github)
- [Remote Machines (GPG Agent Forwarding)](#remote-machines-gpg-agent-forwarding)
- [Require touch](#require-touch)
- [Email](#email)
  - [Mailvelope on macOS](#mailvelope-on-macos)
  - [Mutt](#mutt)
- [Reset](#reset)
- [Notes](#notes)
- [Troubleshooting](#troubleshooting)
- [Links](#links)


# Purchase

All YubiKeys except the blue "security key" model are compatible with this guide. NEO models are limited to 2048-bit RSA keys. Compare YubiKeys [here](https://www.yubico.com/products/yubikey-hardware/compare-products-series/). Yubico have also just released a press release and blog post about supporting resident ssh keys on their Yubikeys including blue "security key 5 NFC" with OpenSSH 8.2 or later, see [here](https://www.yubico.com/blog/github-now-supports-ssh-security-keys/) for details.

To verify a YubiKey is genuine, open a [browser with U2F support](https://support.yubico.com/support/solutions/articles/15000009591-how-to-confirm-your-yubico-device-is-genuine-with-u2f) to [https://www.yubico.com/genuine/](https://www.yubico.com/genuine/). Insert a Yubico device, and select *Verify Device* to begin the process. Touch the YubiKey when prompted, and if asked, allow it to see the make and model of the device. If you see *Verification complete*, the device is authentic.

This website verifies YubiKey device attestation certificates signed by a set of Yubico certificate authorities, and helps mitigate [supply chain attacks](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20r00killah-and-securelyfitz-Secure-Tokin-and-Doobiekeys.pdf).

You will also need several small storage devices (microSD cards work well) for storing encrypted backups of your keys.

# Prepare environment

To create cryptographic keys, a secure environment that can be reasonably assured to be free of adversarial control is recommended. Here is a general ranking of environments most to least likely to be compromised:

1. Daily-use operating system
1. Virtual machine on daily-use host OS (using [virt-manager](https://virt-manager.org/), VirtualBox, or VMWare)
1. Separate hardened [Debian](https://www.debian.org/) or [OpenBSD](https://www.openbsd.org/) installation which can be dual booted
1. Live image, such as [Debian Live](https://www.debian.org/CD/live/) or [Tails](https://tails.boum.org/index.en.html)
1. Secure hardware/firmware ([Coreboot](https://www.coreboot.org/), [Intel ME removed](https://github.com/corna/me_cleaner))

1. Dedicated air-gapped system with no networking capabilities

This guide uses a standard Mac OSX setup, however, depending on your threat model, you may want to take fewer or more steps to secure it.


**Note** An additional Python package dependency may need to be installed to use [`ykman`](https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide) - `pip install yubikey-manager`

# Entropy

Generating cryptographic keys requires high-quality [randomness](https://www.random.org/randomness/), measured as entropy.

To check the available entropy available on Linux:

```console
cat /proc/sys/kernel/random/entropy_avail
849
```

Most operating systems use software-based pseudorandom number generators. On newer machines there are CPU based hardware random number generators (HRNG) or you can use a separate hardware device like the White Noise or [OneRNG](https://onerng.info/onerng/) will [increase the speed](https://lwn.net/Articles/648550/) of entropy generation and possibly the quality.

From YubiKey firmware version 5.2.3 onwards - which introduces "Enhancements to OpenPGP 3.4 Support" - we can gather additional entropy from the YubiKey itself via the SmartCard interface.

## YubiKey

To feed the system's PRNG with entropy generated by the YubiKey itself, issue:
```console
echo "SCD RANDOM 512" | gpg-connect-agent | sudo tee /dev/random | hexdump -C
```
This will seed the Linux kernel's PRNG with additional 512 bytes retrieved from the YubiKey.

# Creating keys

## Temporary working directory

Create a temporary directory which will be cleared on [reboot](https://en.wikipedia.org/wiki/Tmpfs) and set it as the GnuPG directory:

```console
export GNUPGHOME=$(mktemp -d)
```

Otherwise, to preserve the working environment, set the GnuPG directory to your home folder:

```console
export GNUPGHOME=~/gnupg-workspace
```

## Harden configuration

Create a hardened configuration in the temporary working directory by copying [gpg.conf](gpg-guide/gnupg/gpg.conf) over your local copy:

```console
cp gnupg/gpg.conf $GNUPGHOME/gpg.conf 
```

Disable networking for the remainder of the setup.

# Master key

The first key to generate is the master key. It will be used for certification only: to issue sub-keys that are used for encryption, signing and authentication.

**Important** The master key should be kept offline at all times and only accessed to revoke or issue new sub-keys. Keys can also be generated on the YubiKey itself to ensure no other copies exist.

You'll be prompted to enter and verify a passphrase - keep it handy as you'll need it multiple times later.

Generate a strong passphrase which could be written down in a secure place or memorized:

```console
gpg --gen-random --armor 0 24
ydOmByxmDe63u7gqx2XI9eDgpvJwibNH
```

Use upper case letters for improved readability if they are written down:

```console
tr -dc '[:upper:]' < /dev/urandom | fold -w 20 | head -n1
BSSYMUGGTJQVWZZWOPJG
```

**Important** Save this credential in a permanent, secure place as it will be needed to issue new sub-keys after expiration, and to provision additional YubiKeys.

Generate a new key with GPG, selecting `(8) RSA (set your own capabilities)`, `Certify` capability only and `4096` bit key size.

Do not set the master key to expire - see [Note #3](#notes).

```console
gpg --expert --full-generate-key

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
   (9) ECC and ECC
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (13) Existing key
Your selection? 8

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 0
Key does not expire at all
Is this correct? (y/N) y
```

Input any name and email address:

```console
GnuPG needs to construct a user ID to identify your key.

Real name: Dr Duh
Email address: doc@duh.to
Comment: [Optional - leave blank]
You selected this USER-ID:
    "Dr Duh <doc@duh.to>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o

We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

gpg: /tmp.FLZC0xcM/trustdb.gpg: trustdb created
gpg: key 0xFF3E7D88647EBCDB marked as ultimately trusted
gpg: directory '/tmp.FLZC0xcM/openpgp-revocs.d' created
gpg: revocation certificate stored as '/tmp.FLZC0xcM/openpgp-revocs.d/011CE16BD45B27A55BA8776DFF3E7D88647EBCDB.rev'
public and secret key created and signed.

pub   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                              Dr Duh <doc@duh.to>
```

Export the key ID as a [variable](https://stackoverflow.com/questions/1158091/defining-a-variable-with-or-without-export/1158231#1158231) (`KEYID`) for use later:

```console
export KEYID=0xFF3E7D88647EBCDB
```

# Sign with existing key

(Optional) If you already have a PGP key, you may want to sign the new key with the old one to prove that the new key is controlled by you.

Export your existing key to move it to the working keyring:

```console
gpg --export-secret-keys --armor --output /tmp/new.sec
```

Then sign the new key:

```console
gpg  --default-key $OLDKEY --sign-key $KEYID
```

# Sub-keys

Edit the master key to add sub-keys:

```console
gpg --expert --edit-key $KEYID

Secret key is available.

sec  rsa4096/0xEA5DE91459B80592
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
[ultimate] (1). Dr Duh <doc@duh.to>
```

Use 4096-bit RSA keys.

Use a 1 year expiration for sub-keys - they can be renewed using the offline master key. See [rotating keys](#rotating-keys).

## Signing

Create a [signing key](https://stackoverflow.com/questions/5421107/can-rsa-be-both-used-as-encryption-and-signature/5432623#5432623) by selecting `addkey` then `(4) RSA (sign only)`:

```console
gpg> addkey
Key is protected.

You need a passphrase to unlock the secret key for
user: "Dr Duh <doc@duh.to>"
4096-bit RSA key, ID 0xFF3E7D88647EBCDB, created 2016-05-24

Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
Your selection? 4
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 PM UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Encryption

Next, create an [encryption key](https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php) by selecting `(6) RSA (encrypt only)`:

```console
gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
Your selection? 6
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 PM UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09       usage: E
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Authentication

Finally, create an [authentication key](https://superuser.com/questions/390265/what-is-a-gpg-with-authenticate-capability-used-for).

GPG doesn't provide an authenticate-only key type, so select `(8) RSA (set your own capabilities)` and toggle the required capabilities until the only allowed action is `Authenticate`:

```console
gpg> addkey
Please select what kind of key you want:
   (3) DSA (sign only)
   (4) RSA (sign only)
   (5) Elgamal (encrypt only)
   (6) RSA (encrypt only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (12) ECC (encrypt only)
  (13) Existing key
Your selection? 8

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Sign Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions:

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? A

Possible actions for a RSA key: Sign Encrypt Authenticate
Current allowed actions: Authenticate

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Mon 10 Sep 2018 00:00:00 PM UTC
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
```

Finish by saving the keys.

```console
gpg> save
```

## Add extra identities

(Optional) To add additional email addresses or identities, use `adduid`:

```console
gpg> adduid
Real name: Dr Duh
Email address: DrDuh@other.org
Comment:
You selected this USER-ID:
    "Dr Duh <DrDuh@other.org>"

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

gpg> trust
sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

gpg> uid 1

sec  rsa4096/0xFF3E7D88647EBCDB
created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1)* Dr Duh <doc@duh.to>
[ unknown] (2). Dr Duh <DrDuh@other.org>

gpg> primary

sec  rsa4096/0xFF3E7D88647EBCDB
created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: never       usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: never       usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: never       usage: A
[ultimate] (1)* Dr Duh <doc@duh.to>
[ unknown] (2)  Dr Duh <DrDuh@other.org>

gpg> save
```

By default, the last identity added will be the primary user ID - use `primary` to change that.

# Verify

List the generated secret keys and verify the output:

```console
gpg -K
/tmp.FLZC0xcM/pubring.kbx
-------------------------------------------------------------------------
sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                            Dr Duh <doc@duh.to>
ssb   rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S] [expires: 2018-10-09]
ssb   rsa4096/0x5912A795E90DD2CF 2017-10-09 [E] [expires: 2018-10-09]
ssb   rsa4096/0x3F29127E79649A3D 2017-10-09 [A] [expires: 2018-10-09]
```

Add any additional identities or email addresses you wish to associate using the `adduid` command.

**Tip** Verify with a OpenPGP [key best practice checker](https://riseup.net/en/security/message-security/openpgp/best-practices#openpgp-key-checks):

```console
gpg --export $KEYID | hokey lint
```

The output will display any problems with your key in red text. If everything is green, your key passes each of the tests. If it is red, your key has failed one of the tests.

> hokey may warn (orange text) about cross certification for the authentication key. GPG's [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html) documentation has more detail on cross certification, and gpg v2.2.1 notes "subkey <keyid> does not sign and so does not need to be cross-certified". hokey may also indicate a problem (red text) with `Key expiration times: []` on the primary key (see [Note #3](#notes) about not setting an expiry for the primary key).

# Export secret keys

The master key and sub-keys will be encrypted with your passphrase when exported.

Save a copy of your keys:

```console
gpg --armor --export-secret-keys $KEYID > $GNUPGHOME/mastersub.key

gpg --armor --export-secret-subkeys $KEYID > $GNUPGHOME/sub.key
```

# Revocation certificate

Although we will backup and store the master key in a safe place, it is best practice to never rule out the possibility of losing it or having the backup fail. Without the master key, it will be impossible to renew or rotate subkeys or generate a revocation certificate, the PGP identity will be useless.

Even worse, we cannot advertise this fact in any way to those that are using our keys. It is reasonable to assume this *will* occur at some point and the only remaining way to deprecate orphaned keys is a revocation certificate.

To create the revocation certificate:

``` console
gpg --output $GNUPGHOME/revoke.asc --gen-revoke $KEYID
```

The `revoke.asc` certificate file should be stored (or printed) in a (secondary) place that allows retrieval in case the main backup fails.

# Backup

Once keys are moved to YubiKey, they cannot be moved again! Create an **encrypted** backup of the keyring and consider using a [paper copy](https://www.jabberwocky.com/software/paperkey/) of the keys as an additional backup measure.

**Tip** The ext2 filesystem (without encryption) can be mounted on both Linux and OpenBSD. Consider using a FAT32/NTFS filesystem for MacOS/Windows compatibility instead.


# Export public keys

**Important** Without the *public* key, you will not be able to use GPG to encrypt, decrypt, nor sign messages. However, you will still be able to use YubiKey for SSH authentication.

Reconnect networking and upload to a key server.

**Keyserver**

(Optional) Upload the public key to a [public keyserver](https://debian-administration.org/article/451/Submitting_your_GPG_key_to_a_keyserver):

```console
gpg --export $KEYID | curl -T - https://keys.openpgp.org
```

After some time, the public key will to propagate to [other](https://pgp.key-server.io/pks/lookup?search=doc%40duh.to&fingerprint=on&op=vindex) [servers](https://pgp.mit.edu/pks/lookup?search=doc%40duh.to&op=index).

# Configure Smartcard

Plug in a YubiKey and use GPG to configure it as a smartcard:

```console
gpg --card-edit
Reader ...........: Yubico Yubikey 4 OTP U2F CCID
Application ID ...: D2760001240102010006055532110000
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: [not set]
Language prefs ...: [not set]
Sex ..............: unspecified
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

**Note** If the card is locked, see [Reset](#reset).

**Windows**

Use the [YubiKey Manager](https://developers.yubico.com/yubikey-manager) application (note, this not the similarly named older YubiKey NEO Manager) to enable CCID functionality.

## Change PIN

The [GPG interface](https://developers.yubico.com/PGP/) is separate from other modules on a Yubikey such as the [PIV interface](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html). The GPG interface has its own *PIN*, *Admin PIN*, and *Reset Code* - these should be changed from default values!

Entering the user *PIN* incorrectly three times will cause the PIN to become blocked; it can be unblocked with either the *Admin PIN* or *Reset Code*.

Entering the *Admin PIN* or *Reset Code* incorrectly three times destroys all GPG data on the card. The Yubikey will have to be reconfigured.

Name       | Default Value | Use
-----------|---------------|-------------------------------------------------------------
PIN        | `123456`      | decrypt and authenticate (SSH)
Admin PIN  | `12345678`    | reset *PIN*, change *Reset Code*, add keys and owner information
Reset code | _**None**_      | reset *PIN* ([more information](https://forum.yubico.com/viewtopicd01c.html?p=9055#p9055))

Values are valid up to 127 ASCII characters and must be at least 6 (*PIN*) or 8 (*Admin PIN*, *Reset Code*) characters. See the GnuPG documentation on [Managing PINs](https://www.gnupg.org/howtos/card-howto/en/ch03s02.html) for details.

To update the GPG PINs on the Yubikey:

```console
gpg/card> admin
Admin commands are allowed

gpg/card> passwd
gpg: OpenPGP card no. D2760001240102010006055532110000 detected

1 - change PIN
2 - unblock PIN
3 - change Admin PIN
4 - set the Reset Code
Q - quit

Your selection? 3
PIN changed.

1 - change PIN
2 - unblock PIN
3 - change Admin PIN
4 - set the Reset Code
Q - quit

Your selection? 1
PIN changed.

1 - change PIN
2 - unblock PIN
3 - change Admin PIN
4 - set the Reset Code
Q - quit

Your selection? q
```

The number of retry attempts can be changed with the following command, documented [here](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html#ykman-openpgp-access-set-retries-options-pin-retries-reset-code-retries-admin-pin-retries):

```bash
ykman openpgp access set-retries 5 5 5
```

## Set information

Some fields are optional.

```console
gpg/card> name
Cardholder's surname: Duh
Cardholder's given name: Dr

gpg/card> lang
Language preferences: en

gpg/card> login
Login data (account name): doc@duh.to

gpg/card> list

Application ID ...: D2760001240102010006055532110000
Version ..........: 3.4
Manufacturer .....: unknown
Serial number ....: 05553211
Name of cardholder: Dr Duh
Language prefs ...: en
Sex ..............: unspecified
URL of public key : [not set]
Login data .......: doc@duh.to
Private DO 4 .....: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 0
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]

gpg/card> quit
```

# Transfer keys

**Important** Transferring keys to YubiKey using `keytocard` is a destructive, one-way operation only. Make sure you've made a backup before proceeding: `keytocard` converts the local, on-disk key into a stub, which means the on-disk copy is no longer usable to transfer to subsequent security key devices or mint additional keys.

Previous GPG versions required the `toggle` command before selecting keys. The currently selected key(s) are indicated with an `*`. When moving keys only one key should be selected at a time.

```console
gpg --edit-key $KEYID

Secret key is available.

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>
```

## Signing

You will be prompted for the master key passphrase and Admin PIN.

Select and transfer the signature key.

```console
gpg> key 1

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb* rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>

gpg> keytocard
Please select where to store the key:
   (1) Signature key
   (3) Authentication key
Your selection? 1

You need a passphrase to unlock the secret key for
user: "Dr Duh <doc@duh.to>"
4096-bit RSA key, ID 0xBECFA3C1AE191D15, created 2016-05-24
```

## Encryption

Type `key 1` again to de-select and `key 2` to select the next key:

```console
gpg> key 1

gpg> key 2

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb* rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb  rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>

gpg> keytocard
Please select where to store the key:
   (2) Encryption key
Your selection? 2

[...]
```

## Authentication

Type `key 2` again to deselect and `key 3` to select the last key:

```console
gpg> key 2

gpg> key 3

sec  rsa4096/0xFF3E7D88647EBCDB
    created: 2017-10-09  expires: never       usage: C
    trust: ultimate      validity: ultimate
ssb  rsa4096/0xBECFA3C1AE191D15
    created: 2017-10-09  expires: 2018-10-09  usage: S
ssb  rsa4096/0x5912A795E90DD2CF
    created: 2017-10-09  expires: 2018-10-09  usage: E
ssb* rsa4096/0x3F29127E79649A3D
    created: 2017-10-09  expires: 2018-10-09  usage: A
[ultimate] (1). Dr Duh <doc@duh.to>

gpg> keytocard
Please select where to store the key:
   (3) Authentication key
Your selection? 3
```

Save and quit:

```console
gpg> save
```

# Verify card

Verify the sub-keys have been moved to YubiKey as indicated by `ssb>`:

```console
gpg -K
/tmp.FLZC0xcM/pubring.kbx
-------------------------------------------------------------------------
sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [C]
      Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
uid                            Dr Duh <doc@duh.to>
ssb>  rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S] [expires: 2018-10-09]
ssb>  rsa4096/0x5912A795E90DD2CF 2017-10-09 [E] [expires: 2018-10-09]
ssb>  rsa4096/0x3F29127E79649A3D 2017-10-09 [A] [expires: 2018-10-09]
```
	
# Cleanup

Ensure you have:

* Saved encryption, signing and authentication sub-keys to YubiKey (`gpg -K` should show `ssb>` for sub-keys).
* Saved the YubiKey user and admin PINs which you changed from defaults.
* Saved the password to the GPG master key in a *permanent* location.
* Saved a copy of the master key, sub-keys and revocation certificate on an encrypted volume, to be stored offline.
* Saved the password to that encrypted volume in a separate location.
* Saved a copy of the public key somewhere easily accessible later.

Reboot or [securely delete](http://srm.sourceforge.net/) `$GNUPGHOME` and remove the secret keys from the GPG keyring:

```console
sudo srm -r $GNUPGHOME || sudo rm -rf $GNUPGHOME

gpg --delete-secret-key $KEYID

unset GNUPGHOME
```

**Important** Make sure you have securely erased all generated keys and revocation certificates if an ephemeral enviroment was not used!

# Using keys

Copy the config files from the gnupg folder over the files in $GNUPGHOME:

```console
export GNUPGHOME=$HOME/.gnupg
cp gnupg/* ~/.gnupg/

chmod 600 ~/.gnupg/*.conf
```

Import the public key file:

```console
gpg --import key.asc
gpg: key 0xFF3E7D88647EBCDB: public key "Dr Duh <doc@duh.to>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Or download the public key from a keyserver:

```console
gpg --recv $KEYID
gpg: requesting key 0xFF3E7D88647EBCDB from hkps server hkps.pool.sks-keyservers.net
[...]
gpg: key 0xFF3E7D88647EBCDB: public key "Dr Duh <doc@duh.to>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Edit the master key to assign it ultimate trust by selecting `trust` and `5`:

```console
export KEYID=0xFF3E7D88647EBCDB

gpg --edit-key $KEYID

gpg> trust
pub  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never       usage: C
                               trust: unknown       validity: unknown
sub  4096R/0xBECFA3C1AE191D15  created: 2017-10-09  expires: 2018-10-09  usage: S
sub  4096R/0x5912A795E90DD2CF  created: 2017-10-09  expires: 2018-10-09  usage: E
sub  4096R/0x3F29127E79649A3D  created: 2017-10-09  expires: 2018-10-09  usage: A
[ unknown] (1). Dr Duh <doc@duh.to>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

pub  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never       usage: C
                               trust: ultimate      validity: unknown
sub  4096R/0xBECFA3C1AE191D15  created: 2017-10-09  expires: 2018-10-09  usage: S
sub  4096R/0x5912A795E90DD2CF  created: 2017-10-09  expires: 2018-10-09  usage: E
sub  4096R/0x3F29127E79649A3D  created: 2017-10-09  expires: 2018-10-09  usage: A
[ unknown] (1). Dr Duh <doc@duh.to>

gpg> quit
```

Remove and re-insert YubiKey and check the status:

```console
gpg --card-status
Reader ...........: Yubico YubiKey OTP FIDO CCID 00 00
Application ID ...: D2760001240102010006055532110000
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: Dr Duh
Language prefs ...: en
Sex ..............: unspecified
URL of public key : [not set]
Login data .......: doc@duh.to
Signature PIN ....: not forced
Key attributes ...: rsa4096 rsa4096 rsa4096
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 3 3
Signature counter : 0
Signature key ....: 07AA 7735 E502 C5EB E09E  B8B0 BECF A3C1 AE19 1D15
      created ....: 2016-05-24 23:22:01
Encryption key....: 6F26 6F46 845B BEB8 BDF3  7E9B 5912 A795 E90D D2CF
      created ....: 2016-05-24 23:29:03
Authentication key: 82BE 7837 6A3F 2E7B E556  5E35 3F29 127E 7964 9A3D
      created ....: 2016-05-24 23:36:40
General key info..: pub  4096R/0xBECFA3C1AE191D15 2016-05-24 Dr Duh <doc@duh.to>
sec#  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never
ssb>  4096R/0xBECFA3C1AE191D15  created: 2017-10-09  expires: 2018-10-09
                      card-no: 0006 05553211
ssb>  4096R/0x5912A795E90DD2CF  created: 2017-10-09  expires: 2018-10-09
                      card-no: 0006 05553211
ssb>  4096R/0x3F29127E79649A3D  created: 2017-10-09  expires: 2018-10-09
                      card-no: 0006 05553211
```

`sec#` indicates master key is not available (as it should be stored encrypted offline).

**Note** If you see `General key info..: [none]` in the output instead - go back and import the public key using the previous step.

Encrypt a message to your own key (useful for storing password credentials and other data):

```console
echo "test message string" | gpg --encrypt --armor --recipient $KEYID -o encrypted.txt
```

To encrypt to multiple recipients (or to multiple keys):

```console
echo "test message string" | gpg --encrypt --armor --recipient $KEYID_0 --recipient $KEYID_1 --recipient $KEYID_2 -o encrypted.txt
```

Decrypt the message:

```console
gpg --decrypt --armor encrypted.txt
gpg: anonymous recipient; trying secret key 0x0000000000000000 ...
gpg: okay, we are the anonymous recipient.
gpg: encrypted with RSA key, ID 0x0000000000000000
test message string
```

Sign a message:

```console
echo "test message string" | gpg --armor --clearsign > signed.txt
```

Verify the signature:

```console
gpg --verify signed.txt
gpg: Signature made Wed 25 May 2016 00:00:00 AM UTC
gpg:                using RSA key 0xBECFA3C1AE191D15
gpg: Good signature from "Dr Duh <doc@duh.to>" [ultimate]
Primary key fingerprint: 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
     Subkey fingerprint: 07AA 7735 E502 C5EB E09E  B8B0 BECF A3C1 AE19 1D15
```

Use a [shell function](https://github.com/drduh/config/blob/master/zshrc) to make encrypting files easier:

```
secret () {
        output=~/"${1}".$(date +%s).enc
        gpg --encrypt --armor --output ${output} -r 0x0000 -r 0x0001 -r 0x0002 "${1}" && echo "${1} -> ${output}"
}

reveal () {
        output=$(echo "${1}" | rev | cut -c16- | rev)
        gpg --decrypt --output ${output} "${1}" && echo "${1} -> ${output}"
}
```

```console
secret document.pdf
document.pdf -> document.pdf.1580000000.enc

reveal document.pdf.1580000000.enc
gpg: anonymous recipient; trying secret key 0xFF3E7D88647EBCDB ...
gpg: okay, we are the anonymous recipient.
gpg: encrypted with RSA key, ID 0x0000000000000000
document.pdf.1580000000.enc -> document.pdf
```

# Rotating keys

PGP does not provide forward secrecy - a compromised key may be used to decrypt all past messages. Although keys stored on YubiKey are difficult to steal, it is not impossible - the key and PIN could be taken, or a vulnerability may be discovered in key hardware or random number generator used to create them, for example. Therefore, it is good practice to occassionally rotate sub-keys.

When a sub-key expires, it can either be renewed or replaced. Both actions require access to the offline master key. Renewing sub-keys by updating their expiration date indicates you are still in possession of the offline master key and is more convenient.

Replacing keys, on the other hand, is less convenient but more secure: the new sub-keys will **not** be able to decrypt previous messages, authenticate with SSH, etc. Contacts will need to receive the updated public key and any encrypted secrets need to be decrypted and re-encrypted to new sub-keys to be usable. This process is functionally equivalent to "losing" the YubiKey and provisioning a new one. However, you will always be able to decrypt previous messages using the offline encrypted backup of the original keys.

Neither rotation method is superior and it's up to personal philosophy on identity management and individual threat model to decide which one to use, or whether to expire sub-keys at all. Ideally, sub-keys would be ephemeral: used only once for each encryption, signing and authentication event, however in practice that is not really feasible or worthwhile with YubiKey. Advanced users may want to dedicate an offline device for more frequent key rotations and ease of provisioning.


# SSH

**Important** The `cache-ttl` options do **NOT** apply when using a YubiKey as a smartcard as the PIN is [cached by the smartcard itself](https://dev.gnupg.org/T3362). Therefore, in order to clear the PIN from cache (smartcard equivalent to `default-cache-ttl` and `max-cache-ttl`), you need to unplug the YubiKey.

## Replace agents

To launch `gpg-agent` for use by SSH, use the `gpg-connect-agent /bye` or `gpgconf --launch gpg-agent` commands.

Add these to the shell `rc` file:

```console
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
gpg-connect-agent updatestartuptty /bye > /dev/null
```

On modern systems, `gpgconf --list-dirs agent-ssh-socket` will automatically set `SSH_AUTH_SOCK` to the correct value and is better than hard-coding to `run/user/$UID/gnupg/S.gpg-agent.ssh`, if available:

```console
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

If you use fish, the correct lines for your `config.fish` would look like this (consider putting them into the `is-interactive` block depending on your use case):
```fish
set -x GPG_TTY (tty)
set -x SSH_AUTH_SOCK (gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

Note that if you use `ForwardAgent` for ssh-agent forwarding, `SSH_AUTH_SOCK` only needs to be set on the *local* laptop (workstation), where the YubiKey is plugged in.  On the *remote* server that we SSH into, `ssh` will automatically set `SSH_AUTH_SOCK` to something like `/tmp/ssh-mXzCzYT2Np/agent.7541` when we connect.  We therefore do **NOT** manually set `SSH_AUTH_SOCK` on the server - doing so would break [SSH Agent Forwarding](#remote-machines-ssh-agent-forwarding).

If you use `S.gpg-agent.ssh` (see [SSH Agent Forwarding](#remote-machines-ssh-agent-forwarding) for more info), `SSH_AUTH_SOCK` should also be set on the *remote*. However, `GPG_TTY` should not be set on the *remote*, explanation specified in that section.

## Copy public key

**Note** It is **not** necessary to import the corresponding GPG public key in order to use SSH.

Copy and paste the output from `ssh-add` to the server's `authorized_keys` file:

```console
ssh-add -L
ssh-rsa AAAAB4NzaC1yc2EAAAADAQABAAACAz[...]zreOKM+HwpkHzcy9DQcVG2Nw== cardno:000605553211
```

## (Optional) Save public key for identity file configuration

By default, SSH attempts to use all the identities available via the agent. It's often a good idea to manage exactly which keys SSH will use to connect to a server, for example to separate different roles or [to avoid being fingerprinted by untrusted ssh servers](https://blog.filippo.io/ssh-whoami-filippo-io/). To do this you'll need to use the command line argument `-i [identity_file]` or the `IdentityFile` and `IdentitiesOnly` options in `.ssh/config`.

The argument provided to `IdentityFile` is traditionally the path to the _private_ key file (for example `IdentityFile ~/.ssh/id_rsa`). For the YubiKey - indeed, in general for keys stored in an ssh agent - `IdentityFile` should point to the _public_ key file, `ssh` will select the appropriate private key from those available via the ssh agent. To prevent `ssh` from trying all keys in the agent use the `IdentitiesOnly yes` option along with one or more `-i` or `IdentityFile` options for the target host.

To reiterate, with `IdentitiesOnly yes`, `ssh` will not automatically enumerate public keys loaded into `ssh-agent` or `gpg-agent`. This means `publickey` authentication will not proceed unless explicitly named by `ssh -i [identity_file]` or in `.ssh/config` on a per-host basis.

In the case of YubiKey usage, to extract the public key from the ssh agent:

```console
ssh-add -L | grep "cardno:000605553211" > ~/.ssh/id_rsa_yubikey.pub
```

Then you can explicitly associate this YubiKey-stored key for used with a host, `github.com` for example, as follows:

```console
cat << EOF >> ~/.ssh/config
Host github.com
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_rsa_yubikey.pub
EOF
```

## Connect with public key authentication

```console
ssh git@github.com -vvv
[...]
debug2: key: cardno:000605553211 (0x1234567890),
debug1: Authentications that can continue: publickey
debug3: start over, passed a different list publickey
debug3: preferred gssapi-keyex,gssapi-with-mic,publickey,keyboard-interactive,password
debug3: authmethod_lookup publickey
debug3: remaining preferred: keyboard-interactive,password
debug3: authmethod_is_enabled publickey
debug1: Next authentication method: publickey
debug1: Offering RSA public key: cardno:000605553211
debug3: send_pubkey_test
debug2: we sent a publickey packet, wait for reply
debug1: Server accepts key: pkalg ssh-rsa blen 535
debug2: input_userauth_pk_ok: fp e5:de:a5:74:b1:3e:96:9b:85:46:e7:28:53:b4:82:c3
debug3: sign_and_send_pubkey: RSA e5:de:a5:74:b1:3e:96:9b:85:46:e7:28:53:b4:82:c3
debug1: Authentication succeeded (publickey).
[...]
```

**Tip** To make multiple connections or securely transfer many files, consider using the [ControlMaster](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing) ssh option. Also see [drduh/config/ssh_config](https://github.com/drduh/config/blob/master/ssh_config).

## Import SSH keys

If there are existing SSH keys that you wish to make available via `gpg-agent`, you'll need to import them. You should then remove the original private keys. When importing the key, `gpg-agent` uses the key's filename as the key's label; this makes it easier to follow where the key originated from. In this example, we're starting with just the YubiKey's key in place and importing `~/.ssh/id_rsa`:

```console
ssh-add -l
4096 SHA256:... cardno:00060123456 (RSA)

ssh-add ~/.ssh/id_rsa && rm ~/.ssh/id_rsa
```

When invoking `ssh-add`, it will prompt for the SSH key's passphrase if present, then the `pinentry` program will prompt and confirm for a new passphrase to use to encrypt the converted key within the GPG key store.

The migrated key will be listed in `ssh-add -l`:

```console
ssh-add -l
4096 SHA256:... cardno:00060123456 (RSA)
2048 SHA256:... /Users/username/.ssh/id_rsa (RSA)
```

Or to show the keys with MD5 fingerprints, as used by `gpg-connect-agent`'s `KEYINFO` and `DELETE_KEY` commands:

```console
ssh-add -E md5 -l
4096 MD5:... cardno:00060123456 (RSA)
2048 MD5:... /Users/username/.ssh/id_rsa (RSA)
```

When using the key `pinentry` will be invoked to request the key's passphrase. The passphrase will be cached for up to 10 minutes idle time between uses, to a maximum of 2 hours.

## Remote Machines (SSH Agent Forwarding)

**Note** SSH Agent Forwarding can [add additional risk](https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident/#ssh-agent-forwarding-should-be-disabled) - proceed with caution!

There are two methods for ssh-agent forwarding, one is provided by OpenSSH and the other is provided by GnuPG.

The latter one may be more insecure as raw socket is just forwarded (not like `S.gpg-agent.extra` with only limited functionality; if `ForwardAgent` implemented by OpenSSH is just forwarding the raw socket, then they are insecure to the same degree). But for the latter one, one convenience is that one may forward once and use this agent everywhere in the remote. So again, proceed with caution!

For example, `tmux` does not have some environment variables like `$SSH_AUTH_SOCK` when you ssh into remote and attach an old `tmux` session. In this case if you use `ForwardAgent`, you need to find the socket manually and `export SSH_AUTH_SOCK=/tmp/ssh-agent-xxx/xxxx.socket` for each shell. But with `S.gpg-agent.ssh` in fixed place, one can just use it as ssh-agent in their shell rc file.

### Use ssh-agent 

In the above steps, you have successfully configured a local ssh-agent.

You should now be able use `ssh -A remote` on the _local_ machine to log into _remote_, and should then be able to use YubiKey as if it were connected to the remote machine. For example, using e.g. `ssh-add -l` on that remote machine should show the public key from the YubiKey (note `cardno:`).  (If you don't want to have to remember to use `ssh -A`, you can use `ForwardAgent yes` in `~/.ssh/config`.  As a security best practice, always use `ForwardAgent yes` only for a single `Hostname`, never for all servers.)

### Use S.gpg-agent.ssh

First you need to go through [Remote Machines (GPG Agent Forwarding)](#remote-machines-gpg-agent-forwarding), know the conditions for gpg-agent forwarding and know the location of `S.gpg-agent.ssh` on both the local and the remote.

You may use the command:

```console
gpgconf --list-dirs agent-ssh-socket
```

Then in your `.ssh/config` add one sentence for that remote

```
Host
  Hostname remote-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent.ssh /run/user/1000/gnupg/S.gpg-agent.ssh
  # RemoteForward [remote socket] [local socket]
  # Note that ForwardAgent is not wanted here!
```

After successfully ssh into the remote, you should check that you have `/run/user/1000/gnupg/S.gpg-agent.ssh` lying there.

The in the *remote* you can type in command line or configure in the shell rc file with

```console
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
```

After typing or sourcing your shell rc file, with `ssh-add -l` you should find your ssh public key now.

**Note** In this process no gpg-agent in the remote is involved, hence `gpg-agent.conf` in the remote is of no use. Also pinentry is invoked locally.

### Chained SSH Agent Forwarding

If you use `ssh-agent` provided by OpenSSH and want to forward it into a *third* box, you can just `ssh -A third` on the *remote*.

Meanwhile, if you use `S.gpg-agent.ssh`, assume you have gone through the steps above and have `S.gpg-agent.ssh` on the *remote*, and you would like to forward this agent into a *third* box, first you may need to configure `sshd_config` and `SSH_AUTH_SOCK` of *third* in the same way as *remote*, then in the ssh config of *remote*, add the following lines

```console
Host third
  Hostname third-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent.ssh /run/user/1000/gnupg/S.gpg-agent.ssh
  # RemoteForward [remote socket] [local socket]
  # Note that ForwardAgent is not wanted here!
```

You should change the path according to `gpgconf --list-dirs agent-ssh-socket` on *remote* and *third*.

## GitHub

You can use YubiKey to sign GitHub commits and tags. It can also be used for GitHub SSH authentication, allowing you to push, pull, and commit without a password.

Login to GitHub and upload SSH and PGP public keys in Settings.

To configure a signing key:

	> git config --global user.signingkey $KEYID

Make sure the user.email option matches the email address associated with the PGP identity.

Now, to sign commits or tags simply use the `-S` option. GPG will automatically query YubiKey and prompt you for a PIN.

To authenticate:

**Note** If you encounter the error `gpg: signing failed: No secret key` - run `gpg --card-status` with YubiKey plugged in and try the git command again.


# Remote Machines (GPG Agent Forwarding)

This section is different from ssh-agent forwarding in [SSH](#ssh) as gpg-agent forwarding has a broader usage, not only limited to ssh.

To use YubiKey to sign a git commit on a remote host, or signing email/decrypt files on a remote host, configure and use GPG Agent Forwarding. To ssh through another network, especially to push to/pull from GitHub using ssh, see [Remote Machines (SSH Agent forwarding)](#remote-machines-ssh-agent-forwarding) for more info.

To do this, you need access to the remote machine and the YubiKey has to be set up on the host machine.

After gpg-agent forwarding, it is nearly the same as if YubiKey was inserted in the remote. Hence configurations except `gpg-agent.conf` for the remote can be the same as those for the local.

**Important** `gpg-agent.conf` for the remote is of no use, hence `$GPG_TTY` is of no use too for the remote. The mechanism is that after forwarding, remote `gpg` directly communicates with `S.gpg-agent` without *starting* `gpg-agent` on the remote.

On the remote machine, edit `/etc/ssh/sshd_config` to set `StreamLocalBindUnlink yes`

**Optional** If you do not have root access to the remote machine to edit `/etc/ssh/sshd_config`, you will need to remove the socket (located at `gpgconf --list-dir agent-socket`) on the remote machine before forwarding works. For example, `rm /run/user/1000/gnupg/S.gpg-agent`. Further information can be found on the [AgentForwarding GNUPG wiki page](https://wiki.gnupg.org/AgentForwarding).

Import public keys to the remote machine. This can be done by fetching from a keyserver. On the local machine, copy the public keyring to the remote machine:

```console
scp ~/.gnupg/pubring.kbx remote:~/.gnupg/
```

On modern distributions, such as Fedora 30, there is typically no need to also set `RemoteForward` in `~/.ssh/config` as detailed in the next chapter, because the right thing actually happens automatically.

If any error happens (or there is no `gpg-agent.socket` in the remote) for modern distributions, you may go through the configuration steps in the next section.

# Require touch

**Note** This is not possible on YubiKey NEO.

By default, YubiKey will perform encryption, signing and authentication operations without requiring any action from the user, after the key is plugged in and first unlocked with the PIN.

To require a touch for each key operation, install [YubiKey Manager](https://developers.yubico.com/yubikey-manager/) and recall the Admin PIN:

**Note** Older versions of YubiKey Manager use `touch` instead of `set-touch` in the following commands.

Authentication:

```console
ykman openpgp keys set-touch aut on
```

Signing:

```console
ykman openpgp keys set-touch sig on
```

Encryption:

```console
ykman openpgp keys set-touch enc on
```

Depending on how the YubiKey is going to be used, you may want to look at the policy options for each of these and adjust the above commands accordingly. They can be viewed with the following command:

```
ykman openpgp keys set-touch -h
Usage: ykman openpgp keys set-touch [OPTIONS] KEY POLICY

  Set touch policy for OpenPGP keys.

  KEY     Key slot to set (sig, enc, aut or att).
  POLICY  Touch policy to set (on, off, fixed, cached or cached-fixed).

  The touch policy is used to require user interaction for all operations using the private key on the YubiKey. The touch policy is set individually for each key slot. To see the current touch policy, run

      ykman openpgp info

  Touch policies:

  Off (default)   No touch required
  On              Touch required
  Fixed           Touch required, can't be disabled without a full reset
  Cached          Touch required, cached for 15s after use
  Cached-Fixed    Touch required, cached for 15s after use, can't be disabled
                  without a full reset

Options:
  -a, --admin-pin TEXT  Admin PIN for OpenPGP.
  -f, --force           Confirm the action without prompting.
  -h, --help            Show this message and exit.
```

If the YubiKey is going to be used within an email client that opens and verifies encrypted mail, `Cached` or `Cached-Fixed` may be desirable.

YubiKey will blink when it is waiting for a touch. On Linux you can also use [yubikey-touch-detector](https://github.com/maximbaz/yubikey-touch-detector) to have an indicator or notification that YubiKey is waiting for a touch.

# Email

GPG keys on YubiKey can be used with ease to encrypt and/or sign emails and attachments using [Thunderbird](https://www.thunderbird.net/), [Enigmail](https://www.enigmail.net) and [Mutt](http://www.mutt.org/). Thunderbird supports OAuth 2 authentication and can be used with Gmail. See [this guide](https://ssd.eff.org/en/module/how-use-pgp-linux) from EFF for detailed instructions. Mutt has OAuth 2 support since version 2.0.

## Mailvelope on macOS

[Mailvelope](https://www.mailvelope.com/en) allows GPG keys on YubiKey to be used with Gmail and others.

**Important** Mailvelope [does not work](https://github.com/drduh/YubiKey-Guide/issues/178) with the `throw-keyids` option set in `gpg.conf`.

On macOS, install gpgme using Homebrew:

```console
brew install gpgme
```

To allow Chrome to run gpgme, edit `~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/gpgmejson.json` and add:

```json
{
    "name": "gpgmejson",
    "description": "Integration with GnuPG",
    "path": "/usr/local/bin/gpgme-json",
    "type": "stdio",
    "allowed_origins": [
        "chrome-extension://kajibbejlbohfaggdiogboambcijhkke/"
    ]
}
```

Edit the default path to allow Chrome to find GPG:

```console
sudo launchctl config user path /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

Finally, install the [Mailvelope extension](https://chrome.google.com/webstore/detail/mailvelope/kajibbejlbohfaggdiogboambcijhkke) from the Chrome app store.

## Mutt

Mutt has both CLI and TUI interfaces, and the latter provides powerful functions for daily email processing. In addition, PGP can be integrated such that signing/encryption/verifying/decryption can be done without leaving TUI.

To enable GnuPG support, one can just use the config file `gpg.rc` provided by mutt, usually located at `/usr/share/doc/mutt/samples/gpg.rc` after installation. One only needs to edit the file on options like `pgp_default_key`, `pgp_sign_as` and `pgp_autosign`. After editting one can `source` this rcfile in their main `muttrc` to use it.

**Important** If one uses `pinentry-tty` as one's pinentry program in `gpg-agent.conf`, it would mess with one's Mutt TUI, as reported. This is because Mutt TUI uses curses while tty output may harm the format. It is recommended to use `pinentry-curses` or other graphic pinentry program.

# Reset

If PIN attempts are exceeded, the card is locked and must be [reset](https://developers.yubico.com/ykneo-openpgp/ResetApplet.html) and set up again using the encrypted backup.

Copy the following script to a file and run `gpg-connect-agent --run $file` to lock and terminate the card. Then re-insert YubiKey to reset.

```console
/hex
scd serialno
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 e6 00 00
scd apdu 00 44 00 00
/echo Card has been successfully reset.
```

Or use `ykman` (sometimes in `~/.local/bin/`):

```console
ykman openpgp reset
WARNING! This will delete all stored OpenPGP keys and data and restore factory settings? [y/N]: y
Resetting OpenPGP data, don't remove your YubiKey...
Success! All data has been cleared and default PINs are set.
PIN:         123456
Reset code:  NOT SET
Admin PIN:   12345678
```

# Notes

1. YubiKey has two configurations: one invoked with a short press, and the other with a long press. By default, the short-press mode is configured for HID OTP - a brief touch will emit an OTP string starting with `cccccccc`. If you rarely use the OTP mode, you can swap it to the second configuration via the YubiKey Personalization tool. If you *never* use OTP, you can disable it entirely using the [YubiKey Manager](https://developers.yubico.com/yubikey-manager) application (note, this not the similarly named older YubiKey NEO Manager).
1. Programming YubiKey for GPG keys still lets you use its other configurations - [U2F](https://en.wikipedia.org/wiki/Universal_2nd_Factor), [OTP](https://www.yubico.com/faq/what-is-a-one-time-password-otp/) and [static password](https://www.yubico.com/products/services-software/personalization-tools/static-password/) modes, for example.
1. Setting an expiry essentially forces you to manage your subkeys and announces to the rest of the world that you are doing so. Setting an expiry on a primary key is ineffective for protecting the key from loss - whoever has the primary key can simply extend its expiry period. Revocation certificates are [better suited](https://security.stackexchange.com/questions/14718/does-openpgp-key-expiration-add-to-security/79386#79386) for this purpose. It may be appropriate for your use case to set expiry dates on subkeys.
1. To switch between two or more identities on different keys - unplug the first key and restart gpg-agent, ssh-agent and pinentry with `pkill gpg-agent ; pkill ssh-agent ; pkill pinentry ; eval $(gpg-agent --daemon --enable-ssh-support)`, then plug in the other key and run `gpg-connect-agent updatestartuptty /bye` - then it should be ready for use.
1. To use yubikeys on more than one computer with gpg: After the initial setup, import the public keys on the second workstation. Confirm gpg can see the card via `gpg --card-status`, Trust the public keys you imported ultimately (as above). At this point `gpg --list-secret-keys` should show your (trusted) key.

# Troubleshooting

- Use `man gpg` to understand GPG options and command-line flags.

- To get more information on potential errors, restart the `gpg-agent` process with debug output to the console with `pkill gpg-agent; gpg-agent --daemon --no-detach -v -v --debug-level advanced --homedir ~/.gnupg`.

- If you encounter problems connecting to YubiKey with GPG - try unplugging and re-inserting YubiKey, and restarting the `gpg-agent` process.

- If you receive the error, `gpg: decryption failed: secret key not available` - you likely need to install GnuPG version 2.x. Another possibility is that there is a problem with the PIN, e.g. it is too short or blocked.

- If you receive the error, `Yubikey core error: no yubikey present` - make sure the YubiKey is inserted correctly. It should blink once when plugged in.

- If you still receive the error, `Yubikey core error: no yubikey present` - you likely need to install newer versions of yubikey-personalize as outlined in [Required software](#required-software).

- If you receive the error, `Yubikey core error: write error` - YubiKey is likely locked. Install and run yubikey-personalization-gui to unlock it.

- If you receive the error, `Key does not match the card's capability` - you likely need to use 2048 bit RSA key sizes.

- If you receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - make sure you replaced `ssh-agent` with `gpg-agent` as noted above.

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - [run the command](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=835394) `gpg-connect-agent updatestartuptty /bye`

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - edit `~/.gnupg/gpg-agent.conf` to set a valid `pinentry` program path, e.g. `pinentry-program /usr/local/bin/pinentry-mac` on macOS.

- If you receive the error, `The agent has no identities` from `ssh-add -L`, make sure you have installed and started `scdaemon`.

- If you receive the error, `Error connecting to agent: No such file or directory` from `ssh-add -L`, the UNIX file socket that the agent uses for communication with other processes may not be set up correctly. On Debian, try `export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"`. Also see that `gpgconf --list-dirs agent-ssh-socket` is returning single path, to existing `S.gpg-agent.ssh` socket.

- If you receive the error, `Permission denied (publickey)`, increase ssh verbosity with the `-v` flag and ensure the public key from the card is being offered: `Offering public key: RSA SHA256:abcdefg... cardno:00060123456`. If it is, ensure you are connecting as the right user on the target system, rather than as the user on the local system. Otherwise, be sure `IdentitiesOnly` is not [enabled](https://github.com/FiloSottile/whosthere#how-do-i-stop-it) for this host.

- If SSH authentication still fails - add up to 3 `-v` flags to the `ssh` client to increase verbosity.

- If it still fails, it may be useful to stop the background `sshd` daemon process service on the server (e.g. using `sudo systemctl stop sshd`) and instead start it in the foreground with extensive debugging output, using `/usr/sbin/sshd -eddd`. Note that the server will not fork and will only process one connection, therefore has to be re-started after every `ssh` test.

- If you receive the error, `Please insert the card with serial number: *` see [using of multiple keys](#using-multiple-keys).

- If you receive the error, `There is no assurance this key belongs to the named user` or `encryption failed: Unusable public key` use `gpg --edit-key` to set `trust` to `5 = I trust ultimately`.
  - If, when you try the above `--edit-key` command, you get the error 
    `Need the secret key to do this.`, you can manually specify trust for the key in
    `~/.gnupg/gpg.conf` by using the `trust-key [your key ID]` directive.

- If, when using a previously provisioned YubiKey on a new computer with `pass`, you see the
  following error on `pass insert`:
    ```
    gpg: 0x0000000000000000: There is no assurance this key belongs to the named user
    gpg: [stdin]: encryption failed: Unusable public key
    ```
    you need to adjust the trust associated with the key. See the above bullet.

- If you receive the error, `gpg: 0x0000000000000000: skipped: Unusable public key` or `encryption failed: Unusable public key` the sub-key may be expired and can no longer be used to encrypt nor sign messages. It can still be used to decrypt and authenticate, however.

- Refer to Yubico article [Troubleshooting Issues with GPG](https://support.yubico.com/hc/en-us/articles/360013714479-Troubleshooting-Issues-with-GPG) for additional guidance.


# Links

* https://alexcabal.com/creating-the-perfect-gpg-keypair/
* https://blog.habets.se/2013/02/GPG-and-SSH-with-Yubikey-NEO
* https://blog.josefsson.org/2014/06/23/offline-gnupg-master-key-and-subkeys-on-yubikey-neo-smartcard/
* https://blog.onefellow.com/post/180065697833/yubikey-forwarding-ssh-keys
* https://developers.yubico.com/PGP/
  * https://developers.yubico.com/PGP/Card_edit.html
* https://developers.yubico.com/yubikey-personalization/
* https://evilmartians.com/chronicles/stick-with-security-yubikey-ssh-gnupg-macos
* https://gist.github.com/ageis/14adc308087859e199912b4c79c4aaa4
* https://github.com/herlo/ssh-gpg-smartcard-config
* https://github.com/tomlowenthal/documentation/blob/master/gpg/smartcard-keygen.md
* https://help.riseup.net/en/security/message-security/openpgp/best-practices
* https://jclement.ca/articles/2015/gpg-smartcard/
* https://rnorth.org/gpg-and-ssh-with-yubikey-for-mac
* https://trmm.net/Yubikey
* https://www.bootc.net/archives/2013/06/09/my-perfect-gnupg-ssh-agent-setup/
* https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/
* https://www.hanselman.com/blog/HowToSetupSignedGitCommitsWithAYubiKeyNEOAndGPGAndKeybaseOnWindows.aspx
* https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/
* https://mlohr.com/gpg-agent-forwarding/
* https://www.ingby.com/?p=293
* https://support.yubico.com/support/solutions/articles/15000027139-yubikey-5-2-3-enhancements-to-openpgp-3-4-support


This guide is based on https://github.com/drduh/YubiKey-Guide/ used under license:

```console
The MIT License (MIT)

Copyright (c) 2016 drduh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```