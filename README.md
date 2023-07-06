# PrivMail: A Privacy-Preserving Framework for Secure Emails

This repository contains building blocks for our PrivMail framework. Details of the implementation will be available later in a separate publication.

**Warning:** This code is **not** meant to be used for a productive environment and is intended for testing and demonstration purposes only.

## Directory Structure

### Thunderbird-Plugin

This project is an implementation of a Thunderbird plugin/add-on, which enables the user to send and reconstruct PrivMail emails. Note that PrivMail search functionality is not part of this project, but the plugin works with regular email services for sending and receiving emails. See the respective `README.md` for more details on how to load and use the plugin.

### Sender-Client-Proxy

This project is an implementation of a proxy service for sending PrivMail emails similar to the Thunderbird plugin. The advantage is that the proxy works with any email client software or even with a simple script. See the respective `README.md` for more details on how to setup and configure the proxy.

### Receiver-Scripts

This project contains several scripts useful for PrivMail. See the respective `README.md` files for more details.

### Receiver-SMTP-Server

This project is an implementation of a SMTP server for PrivMail, which stores the received emails in separate files in a specific format separating PrivMail information, such as the secret shares and buckets. These files are inputs for some of the scripts mentioned above and for the PrivMail search implementation covered below.

In addition, this server is useful for testing the proxy service for sending PrivMail emails locally without the need to use actual email services and Internet. In the following, we give an example of how to do this for two servers using [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/).

1. Create two empty directories where the secret shared emails are stores (in practice these would be on different machines managed by the two different non-colluding service providers):

```bash
mkdir rss1_mail_data rss2_mail_data
```

2. Create the following `docker-compose.yml` file and place it at the root of this repository.

```yaml
services:
  scp:
    build: Sender-Client-Proxy
    container_name: scp
    command: -m
    stdin_open: true
    tty: true
    ports:
      - "55001:55001"

  rss1:
    build: Receiver-SMTP-Server
    container_name: rss1
    stdin_open: true
    tty: true
    volumes:
      - ./rss1_mail_data:/home/appuser/mail_data:rw

  rss2:
    build: Receiver-SMTP-Server
    container_name: rss2
    stdin_open: true
    tty: true
    volumes:
      - ./rss2_mail_data:/home/appuser/mail_data:rw
```

3. Create the following `destination_address_map.yaml` file and place it in the [Sender-Client-Proxy](Sender-Client-Proxy/) directory.

```yaml
USERS:
  receiver@proxy:
  - DESTINATION: receiver@rss1
    SERVER: rss1
    PORT: 55010
  - DESTINATION: receiver@rss2
    SERVER: rss2
    PORT: 55010
```

4. Copy the `config_example.yaml` to `config.yaml` in the [Sender-Client-Proxy](Sender-Client-Proxy/) directory (the example values work here because our server has no authentication layer):

```bash
cp Sender-Client-Proxy/config_example.yaml Sender-Client-Proxy/config.yaml
```

5. Build the images:

```bash
docker-compose build
```

6. Run the containers in the background:

```bash
docker-compose up -d
```

7. Send emails to the proxy using the address `receiver@proxy` (or however you configured in the `destination_address_map.yaml`) and see the secret shared emails in the two directories. An easy way to send emails is our simple [send_mail.py](Sender-Client-Proxy/test/send_mail.py) script, where you only need to change the `targets` value to `['receiver@proxy']` and then run it:

```bash
Sender-Client-Proxy/test/send_mail.py
```

### Search-with-MOTION

This project implements the PrivMail search functionality as a proof-of-concept (PoC) for benchmark purposes using the [MOTION](https://encrypto.de/code/MOTION) framework. The software reads the secret shared emails from a directory and expects them to be in the format of how the PrivMail SMTP server produces them (see above). In addition, the software takes the search query and search index file as inputs expecting them to be in the format that the respective scripts (in [Receiver-Scripts](Receiver-Scripts/)) produce them. The full set of options are below:

```
Allowed options:
  -h [ --help ]                   produce help message
  -l [ --disable-logging ]        disable logging to file
  -p [ --print-configuration ]    print configuration
  -f [ --configuration-file ] arg configuration file, other arguments will
                                  overwrite the parameters read from the
                                  configuration file
  --my-id arg                     my party id
  --parties arg                   info (id,IP,port) for each party e.g.,
                                  --parties 0,127.0.0.1,23000 1,127.0.0.1,23001
  --search-mode arg (=normal)     choose from search mode options:
                                  [normal|hidden|bucket|index]
  --query-file-path arg           get party's path for query file, include path
                                  e.g. ../../../privmail-incoming-proxy/secret_
                                  shared_query_share1/query_test_file_1.yaml
  --mail-dir-path arg             get party's mail directory path, include path
                                  e.g. ../../../privmail-smtp-server/mail_data
  --index-file-path arg           get party's path for index file, include path
                                  e.g. ../../../privmail-incoming-proxy/index-f
                                  iles/index_file_1.yaml
  --json-path arg                 define path to the benchmarks json file
```

Note that in order to build the binary, you need to install the MOTION library on your machine, see [this](https://github.com/encryptogroup/MOTION/blob/dev/README.md#installation) for more information.

## Disclaimer

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.
