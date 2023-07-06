PrivMail Receiver SMTP Server (RSS)
===================================

PrivMail Receiver SMTP Server (RSS) is a custom Python SMTP server.

## Run with Docker

The recommended way to run RSS is in a Docker container. First, build the image (one time operation) with:

```
docker build -t rss-image .
```

Now you can start the container:

```
docker run -v "$(pwd)"/mail_data:/home/appuser/mail_data:rw -p 55010:55010 -it rss-image
```

By default, RSS is available at `localhost` listening port `55010` and the emails are stored in the `mail_data` directory. Both of these settings can be modified in the `docker run` command as well as the log level. Use the option `-h` to get further details:

```
docker run -it rss-image -h
```

### Run locally

If you want to run RSS locally (e.g., when developing), just simply run:

```
python3 smtp_server.py
```

Note that you must have all the required packages installed listed in `requirements.txt`.

To get details of the options, run:

```
python3 smtp_server.py -h
```

## Usage

You can configure your favorite email client (e.g., Thunderbird) to use RSS as the *Outgoing Server* (no authentication) or use the script located in `test` folder to send emails.
