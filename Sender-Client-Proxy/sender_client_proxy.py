"""PrivMail Sender Client Proxy (SCP) Python script."""

import argparse
import logging
import textwrap
import secrets
import asyncio
import email.parser
import email.message

import aiosmtpd.controller  # type: ignore
import aiosmtplib
import yaml

import privmailcommons.shared as shr  # type: ignore


logging.basicConfig()
log = logging.getLogger('scpproxy')

with open('destination_address_map.yaml', 'r') as stream:
    DESTINATION_ADDRESS_MAP = yaml.safe_load(stream)

with open('config.yaml') as f:
    config = yaml.safe_load(f)

default_server = config['SERVER']
default_port = config['PORT']
default_username = config.get('USERNAME', "")
default_password = config.get('PASSWORD', "")


class ProxySMTPHandler:
    """Process incoming SMTP email data and send the subject and body as secret shares to the receiver."""

    def __init__(self, proxy_mode=True):
        """Create the handler."""
        self.proxy_mode = proxy_mode
        # True: For standard SMTP servers (default)
        # False: For local usage (e.g., custom SMTP server like RSS)

    async def handle_DATA(self, server, session, envelope):  # pylint: disable=C0103
        """Handle received emails."""
        del server, session  # Unused arguments

        log.info(f"Proxy mode running on standard SMTP mode: {self.proxy_mode}")
        log.info(f"Got mail from {envelope.mail_from}")

        msg = email.parser.BytesParser(policy=email.policy.SMTP).parsebytes(envelope.content)
        msg_string: str = msg.get_content()
        log.debug(f"Email body as a string: \"{msg_string}\"")

        # Loop over each target recipient
        for recipient in envelope.rcpt_tos:
            # NOTE: Because rcpttos doesn't separate To, Cc, and Bcc, we just handle them equally here
            user_list = DESTINATION_ADDRESS_MAP['USERS']

            if recipient in user_list.keys():
                log.info("Recipient found from the Destination Address Map, proceeding to secret share the email")
                targets_for_shares = user_list.get(recipient)
                self._secret_share_email(msg, targets_for_shares, envelope)
            else:
                log.warning(f"Recipient \"{recipient}\" was not found from the Destination Address Map, "
                            "proceeding to regular send (unencrypted!)")
                # Just send the original content (no secret sharing)
                asyncio.ensure_future(
                    asyncio.create_task(self.wrapper(envelope.mail_from, recipient, envelope.content,
                                                     default_server, default_port, default_username,
                                                     default_password, self.proxy_mode)
                                        )
                )

        return '250 OK'

    def _secret_share_email(self, msg, targets_for_shares, envelope):
        """Split the email data to N secret shares and send the shares to the targets."""
        msg_string = msg.get_content()
        N = len(targets_for_shares)  # pylint: disable=C0103
        # Construct the shares for the body
        body_shares = shr.construct_shares(msg_string, N, log)

        log.info("Secret shares constructed for the body")

        # Remove ALL whitespace characters (spaces, tabs, newlines, returns, formfeeds)
        truncated_msg_string = ' '.join(msg_string.split())

        # Construct the shares for the truncated body
        truncated_body_shares = shr.construct_shares(truncated_msg_string, N, log, True)

        # Make everything lowercase and remove certain characters when ending a sentence
        truncated_msg_string = truncated_msg_string.lower() \
                                                   .replace('. ', ' ') \
                                                   .replace(', ', ' ') \
                                                   .replace(': ', ' ') \
                                                   .replace('; ', ' ') \
                                                   .replace('? ', ' ') \
                                                   .replace('! ', ' ')

        # Remove AGAIN all the whitespace characters (spaces, tabs, newlines, returns, formfeeds)
        truncated_msg_string = ' '.join(truncated_msg_string.split())

        log.info("Secret shares constructed for the truncated body")

        # Construct the shares for each distinct word and put in buckets
        distinct_words_list = shr.separate_words_from_text(truncated_msg_string)

        buckets = {}
        for _ in range(len(distinct_words_list)):
            # Take words out of the list in random order (in order to hide the order)
            random_word = secrets.choice(distinct_words_list)

            # Remove the word from the list to get a new random word in the next round
            distinct_words_list.remove(random_word)

            # Add the word and place indices in the right bucket
            bucketed_random_word = shr.bucket_keyword(random_word[0], log)
            if len(bucketed_random_word) == 0:
                continue

            if len(bucketed_random_word) not in buckets:
                buckets[len(bucketed_random_word)] = [(bucketed_random_word, random_word[1])]
            else:
                buckets[len(bucketed_random_word)].append((bucketed_random_word, random_word[1]))

        log.debug(f"BUCKETS: {buckets}")

        # Secret share each word individually
        bucket_shares = {}
        for bucket_size in buckets:
            block_word_shares = []
            for word in buckets[bucket_size]:
                block_word_shares.append(shr.construct_shares(word[0], N, log, True))
                # NOTE: The indices in word[1] are ignored now but are useful for following extensions
            bucket_shares[bucket_size] = block_word_shares

        log.debug(f"BUCKET shares: {bucket_shares}")

        log.info("Secret shares constructed for the words in the buckets")

        # Construct the shares for the subject
        subject_shares = shr.construct_shares(msg['Subject'], N, log)

        log.info("Secret shares constructed for the subject")

        self._send_each_shares(targets_for_shares,
                               msg,
                               subject_shares,
                               body_shares,
                               truncated_body_shares,
                               bucket_shares,
                               envelope)

    def _send_each_shares(self,                     # pylint: disable=R0913
                          targets_for_shares,
                          msg,
                          subject_shares,
                          body_shares,
                          truncated_body_shares,
                          bucket_shares,
                          envelope):
        """Send the shares to the targets."""
        # Construct uid with length UID_BYTE_LEN
        uid = shr.construct_uid(shr.UID_BYTE_LEN)

        for i, target_for_share in enumerate(targets_for_shares):
            msg_with_share = email.message.EmailMessage()

            # 1. Get outgoing SMTP server information and credentials
            server = target_for_share.get('SERVER', default_server)
            port = target_for_share.get('PORT', default_port)
            username = target_for_share.get('USERNAME', default_username)
            password = target_for_share.get('PASSWORD', default_password)

            # 2. Copy the required fields from the original email
            msg_with_share['From'] = msg['From']
            msg_with_share['To'] = msg['To']
            if msg['Cc']:
                msg_with_share['Cc'] = msg['Cc']
            # NOTE: Maybe add more fields later?

            # Add uid and secret share into the subject field
            msg_with_share['Subject'] = uid + subject_shares[i]

            # 3. Add the body shares as content
            email_content_string = ""

            # The normal body
            email_content_string += "\n".join([shr.START, *textwrap.wrap(body_shares[i],
                                               shr.CHAR_PER_LINE), shr.END])

            # The truncated body
            email_content_string += "\n\n" + "\n".join([shr.START_TRUNCATED,
                                                       *textwrap.wrap(truncated_body_shares[i],
                                                        shr.CHAR_PER_LINE), shr.END_TRUNCATED])

            # The buckets
            for bucket_size in bucket_shares:
                bucket_block_string_list = []
                bucket_block_string_list.append(shr.START_BUCKET.format(bucket_size))

                for word in bucket_shares[bucket_size]:
                    bucket_block_string_list.append(word[i])

                bucket_block_string_list.append(shr.END_BUCKET.format(bucket_size))
                email_content_string += "\n\n" + "\n".join(bucket_block_string_list)

            msg_with_share.set_content(email_content_string)

            log.debug(f"Final full email:\n{msg_with_share}")

            # 4. Create the sending task
            if envelope.mail_from != username:
                log.warning(f"The original sender {envelope.mail_from} is not the owner of the "
                            f"outgoing SMTP server. Changing the authenticated sender to {username}.")

            asyncio.ensure_future(
                asyncio.create_task(self.wrapper(username, target_for_share['DESTINATION'],
                                    msg_with_share.as_string(), server, port, username, password,
                                    self.proxy_mode)
                                    )
            )

    async def wrapper(self, mailfrom, rcpttos, data, server, port, user, passwd, mode):  # pylint: disable=R0913
        """Create the email send tasks."""
        try:
            async with aiosmtplib.SMTP(hostname=server, port=port, start_tls=False, use_tls=False) as smtp:
                if mode:
                    await smtp.starttls()
                    await smtp.login(user, passwd)
                await smtp.sendmail(mailfrom, rcpttos, data)
                log.info(f"Email has been successfully sent to {rcpttos}")
        except Exception as exception:
            log.error(f"Sending email to {rcpttos} failed: \"{exception}\"")


def main():
    """Handle the arguments and start the proxy server."""
    parser = argparse.ArgumentParser(description="PrivMail Sender Client Proxy (SCP)")

    # Arguments
    parser.add_argument('-p', "--port", action="store", dest="port", type=int, default=55001,
                        help="Set the listening port")

    parser.add_argument("-l", "--log", dest="logLevel", default='INFO', type=str,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")

    # Setting the --mode flag will enable custom SMTP mode, omitting server authentication
    parser.add_argument('-m', "--mode", action="store_false", dest="proxy_mode", default=True,
                        help="Set this flag to start the server in the custom mode "
                             "(omits the outgoing SMTP server authentication)")

    args = parser.parse_args()
    log.setLevel(getattr(logging, args.logLevel))

    handler = ProxySMTPHandler(args.proxy_mode)
    server = aiosmtpd.controller.Controller(handler, hostname='0.0.0.0', port=args.port)
    server.start()
    input(f"PrivMail Sender Client Proxy (SCP) daemon running at port {args.port}. Press Return to quit...\n")
    server.stop()


if __name__ == "__main__":
    main()
