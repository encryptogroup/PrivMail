"""Privmail Incoming Proxy/ Receiving Client Proxy (RCP) Python script."""

import argparse
import logging
import sys
import time
import datetime
import subprocess

import email
import email.mime.text
import imaplib

import yaml

# Import package from parent directory
sys.path.append('..')
import privmailcommons.shared as shr  # noqa


logging.basicConfig()
log = logging.getLogger('rcp')


def fetch_mail(mail_dict, mime_object, begin, end):
    """Fetch emails from specified server and account."""
    for response_part in mime_object:
        if isinstance(response_part, tuple):
            message = email.message_from_bytes(response_part[1])

            mail_from = message[shr.YAML_STRINGS.FROM.value]
            mail_subject = message[shr.YAML_STRINGS.SUBJECT.value]
            mail_to = message[shr.YAML_STRINGS.TO.value]

            if message.is_multipart():
                mail_content = ''

                for part in message.get_payload():
                    if part.get_content_type() == 'text/plain':
                        mail_content += part.get_payload()

                    # NOTE: Handle multipart emails here

            else:
                mail_content = message.get_payload()

                # Check if mail content follows the scheme of secret shared mails
                result, _ = shr.contains_scheme(mail_content, begin, end)

                if not result:
                    continue

                uid, subject = shr.separate_uid(mail_subject, shr.UID_BYTE_LEN)

                # Save them into the mail dictionary

                # Add subject and mail_content to existing uid
                if uid in mail_dict:
                    mail_dict[uid].append((mail_from, mail_to, subject, mail_content))

                # Add completely new key value pair to dictionary
                else:
                    mail_dict[uid] = [(mail_from, mail_to, subject, mail_content)]

    return mail_dict


def connect_and_fetch(server_address, username, password, begin, end, search_query):  # pylint: disable=R0913
    """Connect to a specified server, log into email account and fetch all secret shared emails.

    Return a dictionary of the form {uid: list[sender, receiver, subject, content]}
    """
    mail_dict = {}

    # 1. Connect to the server and go to its inbox
    mail = imaplib.IMAP4_SSL(server_address)
    mail.login(username, password)
    mail.select('inbox')

    # 2. Search the mailbox for messages that match the keyword and store them in mail_byte_ids
    # Imaplib search returns a result code and a list of mail ids as bytes
    # https://docs.python.org/3/library/imaplib.html
    result, mail_byte_ids = mail.search(None, search_query)

    # Possible result codes: ['OK', 'NO', 'BAD']
    if result != 'OK':
        log.error(f"imaplib.search ERROR: Expected response code 'OK' but received {result}")
        return {}

    # Mail_byte_ids is a single element list.
    # It holds a bytes list of mail ids of form [b' mail_id mail_id ... mail_id'].
    for mail_id in mail_byte_ids[0].split():
        # 3. Fetch the mail objects from the inbox
        result, mime_object = mail.fetch(mail_id, '(RFC822)')
        # The [RFC822] standard defines the messages that represent email messages,
        # they consist of a collection of headers and a body.
        # For more information about the [RFC822] standards refers to this:
        # https://datatracker.ietf.org/doc/html/rfc822

        if result != 'OK':
            log.error(f"imaplib.fetch ERROR: Expected response code 'OK' but received {result}")
            continue

        # 4. Exctract mail content from mime object
        mail_dict = fetch_mail(mail_dict, mime_object, begin, end)

    # 5. Close mailbox and log out of account
    mail.close()
    mail.logout()

    return mail_dict


def reconstruct_emails(mail_dict, start, end):
    """Return a list of email objects from the input dictionary.

    Expects a dictionary of form {key: list[value, ...]}
    """
    # Variables
    mail_shares = []
    subject_shares = []
    sender = []
    receiver = []

    reconstructed_mail_list = []

    # 1. Save sender and mail/subject shares into variables
    # Combine the shares here
    for uid in mail_dict:
        sub_mail_shares = []
        sub_subject_shares = []

        for mail_share in mail_dict.get(uid):

            sender.append(mail_share[0])
            receiver.append(mail_share[1])
            sub_subject_shares.append(mail_share[2])

            result, content = shr.contains_scheme(mail_share[3], start, end)
            if not result:
                log.debug("The content does not contain the scheme or is faulty")
                continue

            sub_mail_shares.append(content)

        mail_shares.append(sub_mail_shares)
        subject_shares.append(sub_subject_shares)

    # 2. Reconstruct mail objects from the shares
    for mail_share, _ in enumerate(mail_shares):
        # Creating new email object
        msg = email.mime.text.MIMEText(shr.reconstruct_shares(mail_shares[mail_share], log))
        msg[shr.YAML_STRINGS.FROM.value] = sender[mail_share]
        msg[shr.YAML_STRINGS.TO.value] = receiver[mail_share]
        msg[shr.YAML_STRINGS.SUBJECT.value] = shr.reconstruct_shares(subject_shares[mail_share], log)

        # Append to the list of reconstructed mails
        reconstructed_mail_list.append(msg)

    return reconstructed_mail_list


def generate_arg_parser():
    """Generate an argument parser that supports basic logLevel arguments as well as IMAPv4 search commands.

    Refer to this link for more information: https://datatracker.ietf.org/doc/html/rfc3501#section-6.4.4).
    """
    parser = argparse.ArgumentParser(
        description="PrivMail Receiver Client Proxy (RCP)")

    # Arguments
    parser.add_argument("-l", "--log", dest="logLevel", default='INFO', type=str,
                        choices=['DEBUG', 'INFO',
                                 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")

    parser.add_argument("--keywords", dest="keywords", type=str, nargs='*', default=['', "ALL", '', ''],
                        help="Set keyword search parameter. Expects four arguments.\
                              Example: Alice,Bob,'' TO,FROM,ALL '',NOT,'' OR,AND")

    parser.add_argument("--stats", dest="stats", action="store_true", default=False,
                        help="Save measurement information in a file")

    parser.add_argument("--silent", dest="silent", action="store_true", default=False,
                        help="Do not show the combined emails")

    return parser.parse_args()


def bad_arguments(argument_list):
    """Check for bad arguments."""
    if len(argument_list) != 4:
        log.error(f"Expected at least four arguments but received: {len(argument_list)}")
        return True
    if len(argument_list[0]) != len(argument_list[1]) or\
       len(argument_list[0]) != len(argument_list[2]):
        log.error(f"Different size argument lists ({argument_list[0]},{argument_list[1]},{argument_list[2]})")
        return True
    if len(argument_list[0]) != 1:
        if len(argument_list[0]) != len(argument_list[3]) + 1:
            log.error(f"Argument list {argument_list[3]} has wrong size")
            return True

        # Append the sequence arguments with empty string, since it should be one item shorter
        argument_list[3].append('')

    return False


def parse_input_arguments(args):
    """Handle the input arguments and return a RFC822 compliant search query."""
    namespace_dict = vars(args)
    search_query = ''

    log.debug(f"Argument parser flags: {namespace_dict}")

    # 1. Create argument list:
    argument_list = []
    for argument in namespace_dict[shr.YAML_STRINGS.KEYWORDS.value]:
        argument_list.append(argument.split(','))

    # 2. Check for bad arguments
    if bad_arguments(argument_list):
        return False, ""

    # 3. Construct IMAPv4 compliant search query
    # Assumes that all arguments have the same length
    for index, _ in enumerate(argument_list[0]):
        for argument in reversed(argument_list):
            if index > len(argument) - 1:
                return True, search_query
            if argument[index].lower() == 'and' or argument[index] == '':
                continue
            search_query += argument[index] + ' '

    return True, search_query


def main():
    """Handle input arguments and receive emails from targets defined in credentials."""
    # 1. Generate argument parser here
    args = generate_arg_parser()

    log.setLevel(getattr(logging, args.logLevel))

    # 2. Parse the input arguments
    result, search_query = parse_input_arguments(args)

    # Check for bad result
    if not result:
        return

    log.info(f"Parsed search query: {search_query}")

    # 3. Handle the received emails and combine them into a mail_list
    combined_dict = {}

    with open('credentials.yaml', encoding='ascii') as credentials_file:
        config = yaml.safe_load(credentials_file)
    servers = config['SERVERS']

    connect_and_fetch_times = []
    combine_share_dictionaries_times = []
    for entry in servers:
        try:
            start_time = time.perf_counter()
            result_dict = connect_and_fetch(entry['ADDRESS'], entry['USERNAME'], entry['PASSWORD'],
                                            shr.START, shr.END, search_query)

            between_time = time.perf_counter()

            combined_dict = shr.combine_share_dictionaries(combined_dict, result_dict)
            end_time = time.perf_counter()

            connect_and_fetch_times.append(between_time - start_time)
            combine_share_dictionaries_times.append(end_time - between_time)
        except Exception as exception:
            log.error(f"Exception: {exception}")

    start_reconstruct_time = time.perf_counter()
    mail_list = reconstruct_emails(combined_dict, shr.START, shr.END)
    end_reconstruct_time = time.perf_counter()

    if not args.silent:
        for mail in mail_list:
            log.info(f"Mail list:\n {mail}")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
    decimal_places = 3
    connect_and_fetch_time = sum(connect_and_fetch_times)
    combine_share_dictionaries_time = sum(combine_share_dictionaries_times)
    reconstruct_time = end_reconstruct_time - start_reconstruct_time

    stats = {}
    stats["script"] = sys.argv[0]
    stats["timestamp"] = timestamp
    stats["number_of_mails"] = len(mail_list)
    stats["connect_and_fetch_time_seconds"] = round(connect_and_fetch_time,
                                                    decimal_places)
    stats["share_dictionary_combination_time_seconds"] = round(combine_share_dictionaries_time,
                                                               decimal_places)
    stats["share_reconstruction_time_seconds"] = round(reconstruct_time,
                                                       decimal_places)
    stats["total_time_seconds"] = round(connect_and_fetch_time +
                                        combine_share_dictionaries_time +
                                        reconstruct_time,
                                        decimal_places)

    if args.stats:
        short_git_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('ascii').strip()
        with open(f"perf_{timestamp}_{short_git_hash}.yaml", 'w', encoding='utf8') as stats_file:
            yaml.dump(stats, stats_file)


if __name__ == "__main__":
    main()
