# Stash

A proxy that caches resources for offline use.

```shell
Usage: stash --cert-file=STRING --key-file=STRING [flags]

Flags:
  -h, --help                 Show context-sensitive help.
      --port=9999            Listen on this port ($STASH_PORT).
      --dir=".stash"         Path to cache directory ($STASH_DIR)
      --hosts=HOSTS,...      Cache responses from these hosts ($STASH_HOSTS)
      --cert-file=STRING     Path to CA certificate file ($STASH_CERT_FILE)
      --key-file=STRING      Path to CA private key file ($STASH_KEY_FILE)
      --log-level="info"     Log level ($STASH_LOG_LEVEL)
      --log-format="text"    Log format ($STASH_LOG_FORMAT)
```

## Installation

The `stash` program can be installed by downloading one of the archives from [the latest release](https://github.com/tschaub/stash/releases).

Extract the archive and place the `stash` executable somewhere on your path.  See a list of available commands by running `stash` in your terminal.

Homebrew users can install the `stash` program with [`brew`](https://brew.sh/):

```shell
brew update
brew install tschaub/tap/stash
```

## Usage

In order to proxy https resources, you'll need to set up a locally trusted development certificate. Fortunately, this is easy with [`mkcert`](https://github.com/FiloSottile/mkcert/).

To install a locally trusted development certificate:

```shell
# install mkcert if you haven't already
brew install mkcert

# set up certificate
mkcert -install
```
Next, you'll need to determine the location of the certificate files.

```shell
# get location of *.pem files
find "$(mkcert -CAROOT)" -name "*.pem"
```

Make note of the location of the certificate `rootCA.pem` and key `rootCA-key.pem` files. You'll use the path to the `rootCA.pem` file in the `--cert-file` argument and the path to `rootCA-key.pem` in the `--key-file` argument to `stash`.

You can use a `.env` file to provide values for the `stash` arguments.

```shell
# example .env file
STASH_CERT_FILE='/path/to/mkcert/rootCA.pem'
STASH_KEY_FILE='/path/to/mkcert/rootCA-key.pem'
STASH_LOG_LEVEL=debug
STASH_HOSTS=example.com,fonts.googleapis.com
```

With a `.env` file like the one above, you can run `stash` with no additional arguments. This would be equivalent to running the following (without a `.env` file):

```shell
stash --cert-file='/path/to/mkcert/rootCA.pem' \
  --key-file='/path/to/mkcert/rootCA-key.pem' \
  --log-level=debug \
  --hosts=example.com,fonts.googleapis.com
```

With `stash` running, you can configure your browser to use it as a proxy. For example, to launch Chrome using `stash` as a proxy do this:

```shell
# assuming Chrome is not already running
open -a "Google Chrome" --args --proxy-server="127.0.0.1:9999"
```
