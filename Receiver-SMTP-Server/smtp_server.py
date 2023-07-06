"""PrivMail Receiver SMTP Server (RSS) Python script."""

import argparse
import logging
import os

import aiosmtpd.controller  # type: ignore
import mailparser  # type: ignore
import yaml

import privmailcommons.shared as shr  # type: ignore


logging.basicConfig()
log = logging.getLogger('rssserver')

FILE_PATH = "mail_data/"


def reconstruct_uid_sequence_dictionary(path):
    """Reconstruct uid-sequence dictionary from mail shares in directory."""
    reconstructed_uid_sequence_dict = {}
    directory = os.listdir(path)

    for file in directory:
        with open(path + file, 'r', encoding='ascii') as yaml_file:
            mail_share_dict = yaml.safe_load(yaml_file)
            if not isinstance(mail_share_dict, dict) or shr.YAML_STRINGS.UID.value not in mail_share_dict:
                continue
            if mail_share_dict[shr.YAML_STRINGS.UID.value] not in reconstructed_uid_sequence_dict:
                reconstructed_uid_sequence_dict[mail_share_dict[shr.YAML_STRINGS.UID.value]] = \
                    mail_share_dict[shr.YAML_STRINGS.SEQUENCE_NUMBER.value]
            elif (
                mail_share_dict[shr.YAML_STRINGS.SEQUENCE_NUMBER.value] !=
                reconstructed_uid_sequence_dict[mail_share_dict[shr.YAML_STRINGS.UID.value]]
            ):
                log.warning(f"Sequence number for {file} does not match the sequence number from dictionary")
    log.info(f"Reconstruct uid_sequence_number_dict: {reconstructed_uid_sequence_dict}")

    return reconstructed_uid_sequence_dict


def update_uid_sequence_dictionary(uid_sequence_number_dict, uid):
    """Update uid-sequence dictionary based on the new uid."""
    if len(uid_sequence_number_dict) == 0:
        uid_sequence_number_dict[uid] = 0   # The starting sequence number is 0
    elif uid not in uid_sequence_number_dict:
        uid_sequence_number_dict[uid] = max(uid_sequence_number_dict.values()) + 1


class CustomSMTPHandler:  # pylint: disable=R0913,R0903
    """A handler class to process incoming SMTP email data and store them in a yaml file."""

    # key: uid, value: sequence_number
    if not os.path.exists(FILE_PATH):
        os.mkdir(FILE_PATH)
    mail_shares_directory = FILE_PATH

    uid_sequence_number_dict = reconstruct_uid_sequence_dictionary(mail_shares_directory)

    async def handle_DATA(self, _, session, envelope):  # pylint: disable=C0103,R0915
        """Handle SMTP email data, extract the different blocks and store them in a file."""
        log.info(f"Receiving message from: {session.peer}")
        log.info(f"Message addressed from: {envelope.mail_from}")
        log.info(f"Message addressed to  : {envelope.rcpt_tos}")
        log.info(f"Message length        : {len(envelope.content)}")
        log.info(f"Message content       : {envelope.content}")

        # 1. Generate dictionary from the received mail data
        mail_dict = {}
        mail_dict[shr.YAML_STRINGS.MAILFROM.value] = envelope.mail_from
        mail_dict[shr.YAML_STRINGS.RCPTTOS.value] = envelope.rcpt_tos

        mail = mailparser.parse_from_bytes(envelope.content)

        contains_scheme, _ = shr.contains_scheme(mail.body, shr.START, shr.END)
        if contains_scheme:
            mail_dict[shr.YAML_STRINGS.UID.value], mail_dict[shr.YAML_STRINGS.SUBJECT.value] = \
                shr.separate_uid(mail.subject, shr.UID_BYTE_LEN)

            update_uid_sequence_dictionary(self.uid_sequence_number_dict,
                                           mail_dict[shr.YAML_STRINGS.UID.value])

            mail_dict[shr.YAML_STRINGS.SEQUENCE_NUMBER.value] =\
                self.uid_sequence_number_dict[mail_dict[shr.YAML_STRINGS.UID.value]]

            log.debug(f"Entries in uid_sequence_number_dict: {self.uid_sequence_number_dict}")

            mail_body = ""
            mail_secret_share_block = ""
            mail_secret_share_truncated_block = ""
            mail_secret_share_bucket_blocks = {}

            secret_share_block_flag = False
            secret_share_truncated_block_flag = False
            secret_share_bucket_block_flag = False
            secret_share_bucket_size = 0

            normal_block_scheme = (shr.START, shr.END)
            truncated_block_scheme = (shr.START_TRUNCATED, shr.END_TRUNCATED)
            bucket_block_scheme = (shr.START_BUCKET, shr.END_BUCKET)

            for line in mail.body.splitlines():
                start_or_end_found_flag = False
                # Handle the normal blocks
                block_result = shr.handle_block_type(line, normal_block_scheme,
                                                     secret_share_block_flag,
                                                     start_or_end_found_flag)

                secret_share_block_flag = block_result[0]
                start_or_end_found_flag = block_result[1]

                # Handle the truncated blocks
                truncated_block_result = shr.handle_block_type(line, truncated_block_scheme,
                                                               secret_share_truncated_block_flag,
                                                               start_or_end_found_flag)

                secret_share_truncated_block_flag = truncated_block_result[0]
                start_or_end_found_flag = truncated_block_result[1]

                # Handle the bucket blocks
                bucket_blocks_result = shr.handle_block_type(line, bucket_block_scheme,
                                                             secret_share_bucket_block_flag,
                                                             start_or_end_found_flag,
                                                             mail_secret_share_bucket_blocks,
                                                             secret_share_bucket_size,
                                                             True)

                secret_share_bucket_block_flag = bucket_blocks_result[0]
                start_or_end_found_flag = bucket_blocks_result[1]
                mail_secret_share_bucket_blocks = bucket_blocks_result[2]
                secret_share_bucket_size = bucket_blocks_result[3]

                if start_or_end_found_flag:
                    continue
                if secret_share_block_flag:
                    mail_secret_share_block += line
                    continue
                if secret_share_truncated_block_flag:
                    mail_secret_share_truncated_block += line
                    continue
                if secret_share_bucket_block_flag:
                    mail_secret_share_bucket_blocks[secret_share_bucket_size].append(line)
                    continue

                # If not in any block, add to the body
                mail_body += line

            if secret_share_block_flag or secret_share_truncated_block_flag:
                log.warning("A secret share block did not have an ending")

            mail_dict[shr.YAML_STRINGS.BODY.value] = mail_body
            mail_dict[shr.YAML_STRINGS.SECRET_SHARE_BLOCK.value] = mail_secret_share_block
            mail_dict[shr.YAML_STRINGS.SECRET_SHARE_TRUNCATED_BLOCK.value] = mail_secret_share_truncated_block

            mail_dict[shr.YAML_STRINGS.SECRET_SHARE_BUCKET_BLOCKS.value] = {}
            for bucket_size in mail_secret_share_bucket_blocks:
                mail_dict[shr.YAML_STRINGS.SECRET_SHARE_BUCKET_BLOCKS.value][bucket_size] = \
                    mail_secret_share_bucket_blocks[bucket_size]

        else:
            mail_dict[shr.YAML_STRINGS.SUBJECT.value] = mail.subject
            mail_dict[shr.YAML_STRINGS.BODY.value] = mail.body

        # 2. Generate a unique path for the new file
        filename = shr.generate_unique_filename(FILE_PATH)

        # 3. Write data into a yaml file of the generated path
        with open(filename, 'w', encoding='ascii') as outfile:
            yaml.dump(mail_dict, outfile, default_flow_style=False)

        return '250 OK'


def main():
    """Handle the arguments and start the SMTP server."""
    parser = argparse.ArgumentParser(description="PrivMail Receiver SMTP Server (RSS)")

    # Arguments
    parser.add_argument('-p', "--port", action="store", dest="port", type=int, default=55010,
                        help="Set the listening port")

    parser.add_argument("-l", "--log", dest="logLevel", default='INFO', type=str,
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")

    args = parser.parse_args()
    log.setLevel(getattr(logging, args.logLevel))

    handler = CustomSMTPHandler()
    server = aiosmtpd.controller.Controller(handler, hostname='0.0.0.0', port=args.port)
    server.start()
    input(f"PrivMail Receiver SMTP Server (RSS) daemon running at port {args.port}. Press Return to quit...\n")
    server.stop()


if __name__ == "__main__":
    main()
