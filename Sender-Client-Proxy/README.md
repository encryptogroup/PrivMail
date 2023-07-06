
PrivMail Sender Client Proxy (SCP)
==================================

PrivMail Sender Client Proxy (SCP) is a Python script that enables secret sharing of emails outsourcing them securely to multiple SMTP servers.

## Configuration

Firstly, configure the outgoing SMTP server by copying/renaming `config_example.yaml` to `config.yaml` and modify it. The `SERVER` is the outgoing mail server address (e.g., `smtp.gmail.com` for Google) and `PORT` is the target port (e.g., `587` for TLS/STARTTLS). The `USERNAME` and `PASSWORD` are your credentials for the mail server. At the moment, we don't support multi-factor authentication (MFA).

In order to configure targets, you need to copy/rename `destination_address_map_example.yaml` to `destination_address_map.yaml` and modify it to your needs. The `USERS` is a map, where a key represents the identifier of the target read from the `To` field of the email and can be basically any string. But since email clients (normally) accept only valid email addresses, it is recommended to set it to something like `[target]@ourproxy.com`. The value is then a list of maps, where `DESTINATION` defines the actual destination address, so for example `[target]@gmail.com` and/or `[target]@outlook.com`. In addition, you can define the outgoing SMTP server information (`SERVER`, `PORT`, `USERNAME`, `PASSWORD`) here separately for each `DESTINATION`, which overwrites the default configuration defined in `config.yaml`.

## Run with Docker

The recommended way to run SCP is in a Docker container. First, build the image (one time operation) with:

```
docker build -t scp-image .
```

Now you can start the container:

```
docker run -p 55001:55001 -it scp-image
```

SCP is now available at `localhost` listening port `55001`. The listening port can be modified by changing the first port number, i.e., `[port]:55001`. You can also change the listening port SCP is using inside the container:

```
docker run -p 55001:[port] -it scp-image --port [port]
```

The log level can be modified with the option `--log`.

SCP supports two different operation modes: the default and the custom mode. The default mode uses the credentials from the `config.yaml` to log into existing *real* outgoing SMTP servers (e.g., Outlook or Gmail) while the custom mode omits the server authentication and just sends the secret shares of the email directly to the server(s). The custom mode is not useful in practice and does not work with *real* outgoing SMTP servers but it is useful for delivering the secret shares directly to custom SMTP servers, e.g., running in `localhost` for experiments. The custom SMTP mode can be enabled with the option `--mode`.

Use the option `-h` for getting the help text.

### Run locally

If you want to run SCP locally (e.g., when developing), just simply run:

```
python3 sender_client_proxy.py
```

Note that you must have all the required packages installed listed in `requirements.txt`.

To get details of the options, run:

```
python3 sender_client_proxy.py -h
```

## Usage

You can configure your favorite email client (e.g., Thunderbird) to use SCP as the *Outgoing Server* (no authentication) or use the script located in `test` folder to send emails.
