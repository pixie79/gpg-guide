# GPG Sign Git Commits

One of the many things GPG allows you to do is sign GIT commits. This provides an audit trail within GIT as to who commited each line of code. This is enhanced by many of the hosted GIT tool sets by allowing users to quickly see if commits are signed and created by appropriate users.

To enable GIT signing it is first recommended that users have an external Yubikey with GPG setup, you can use system held keys but these are not as secure. 

Once you have GPG setup and enabled you need to issue the following commands to setup GIT to make use of GPG.


```console
gpg --list-secret-keys --keyid-format LONG user@example.com
```

```console
sec   rsa4096/30F2B65B9246B6CA 2017-08-18 [SC]
      Key fingerprint = D5E4F29F3275DC0CDA8FFC8730F2B65B9246B6CA
uid                   [ultimate] Mr. Robot <user@example.com>
ssb   rsa4096/B7ABC0813E4028C0 2017-08-18 [E]
```

look for the fingerprint then enter the following commands. Ensure the email address entered matches the email on you GPG key. Replace *XX_fingerprint_XX* with fingerprint from the above output.

```console
git config --global user.name "FirstName Surname"
git config --global user.email "user@example.com"
git config --global user.signingkey XX_fingerprint_XX
git config --global commit.gpgsign true
```


## Gitlab setup

To enable Gitlab to verify your GPG signed commits you need to give Gitlab a copy of your public GPG key. This can be done by doing the following:

```console
gpg --armor --export user@example.com
```

Copy the text output including the lines "-----BEGIN PGP PUBLIC KEY BLOCK-----" and "-----END PGP PUBLIC KEY BLOCK-----", paste them into the empty box at the following url: [https://gitlab.example.com/-/profile/gpg_keys](https://gitlab.example.com/-/profile/gpg_keys)

