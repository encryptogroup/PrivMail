#!/usr/bin/env python3

import email.mime.text
import asyncio
import aiosmtplib

server = 'localhost'
port = 55001
sender = 'SENDER'   # Usually equal to the USERNAME in the config.yaml
targets = ['TARGET-USER-1', sender]
#NOTE: The second target here ensures that the sender receives a plaintext copy of the email (so can be removed)

#msg = email.mime.text.MIMEText('Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed in sapien magna. Sed et ante mollis, dictum lorem sit amet, dapibus erat. Duis in laoreet eros. Phasellus sit amet tellus massa. Cras et augue eu dui tristique venenatis. Quisque tincidunt tempus nisl at ullamcorper. Suspendisse condimentum rutrum enim. Nullam scelerisque in velit pulvinar dictum. Aliquam ultricies a nulla in tristique. Integer dapibus rutrum lobortis. Quisque quis varius eros, et egestas sapien. Mauris ornare nulla non nisi bibendum lobortis. Maecenas efficitur, mauris sit amet aliquet euismod, elit erat accumsan dolor, rhoncus egestas magna purus eu dolor. Morbi rhoncus, elit sit amet semper congue, velit arcu fringilla magna, pellentesque dignissim quam nisi sit amet arcu. Nam hendrerit ex vel ornare sodales. Lorem ipsum dolor sit amet, consectetur adipiscing elit.')
#msg = email.mime.text.MIMEText('A short test email body message.')
msg = email.mime.text.MIMEText("""Hi,

Let this be our \"official\" test email, which looks more like a normal email. \
We also print some special characters in order to see how they work. Now just \
making the email text a bit longer in order it to be a better example. Hopefully \
this represents now more or less regular email body.

Special characters: ? (question mark), # (hashtag), : (colon), % (percentage symbol), ä (a with dots)

Best,
outgoing.scp
""")

msg['Subject'] = 'Test email subject'
msg['From'] = sender
msg['To'] = ', '.join(targets)


async def send_wrapper(msg):
    smtp_client = aiosmtplib.SMTP(hostname=server, port=port)
    await smtp_client.connect()
    await smtp_client.send_message(msg)
    await smtp_client.quit()
    print(f'Mail has been successfully sent to proxy')

def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        asyncio.wait([loop.create_task(send_wrapper(msg))]))
    loop.close()


if __name__ == "__main__":
    main()
