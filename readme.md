## development notes

Use mkcert for local certificate

```shell
# install mkcert
brew install mkcert

# set up certificate
mkcert -install

# get location of files
mkcert -CAROOT
```

Launch Chrome with proxy server set:

```shell
open -a "Google Chrome" --args --proxy-server="127.0.0.1:9999"
```

Ideas:
 * maybe use symbolic link from extensionless file to file with extension to get content-type from the file server
