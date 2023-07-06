#!/usr/bin/env python3

import argparse

import aiosmtplib
import asyncio
import email.mime.text


sender = 'admin@example.com'
receivers = ['info@example.com']

server = 'localhost'
msg = email.mime.text.MIMEText("""Hi,

Let this be our \"official\" test email, which looks more like a normal email. \
We also print some special characters in order to see how they work. Now just \
making the email text a bit longer in order it to be a better example. Hopefully \
this represents now more or less regular email body.

Special characters: ? (question mark), # (hashtag), : (colon), % (percentage symbol), ä (a with dots)

Best,
outgoing.scp
""")

msg['Subject'] = 'Test mail'
msg['From'] = 'admin@example.com'
msg['To'] = 'info@example.com'


async def send_wrapper(msg, port):
    smtp_client = aiosmtplib.SMTP(hostname=server, port=port)
    await smtp_client.connect()
    await smtp_client.send_message(msg)
    await smtp_client.quit()
    print(f'Successfully sent email')


def main():
    """
    A main function to sending a test mail to the Privmail RSS
    """
    parser = argparse.ArgumentParser(description="PrivMail Receiver SMTP Server (RSS)")

    # Arguments
    parser.add_argument('-p', "--port", action="store", dest="port", type=int, default=55010,
                        help="Set the listening port")

    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.wait([loop.create_task(send_wrapper(msg, args.port))]))
    loop.close()


if __name__ == "__main__":
    main()
