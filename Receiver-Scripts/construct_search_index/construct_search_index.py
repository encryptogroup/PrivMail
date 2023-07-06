"""Privmail Construct Search Indexing (CSI) Python script."""

import argparse
import logging
import os
import collections
import itertools
import random
import sys

import yaml

# Import package from parent directory
sys.path.append('..')
import privmailcommons.shared as shr  # noqa


logging.basicConfig()
log = logging.getLogger('csi')


def reconstruct_bucket_blocks(bucket_block_shares, bucket_block_dict):
    """Reconstruct bucket blocks from shares."""
    for share in bucket_block_shares:
        for bucket_size, word_list in share.items():
            # Check if bucket size is valid
            if bucket_size not in shr.BUCKET_SCHEME:
                log.warning(f"Invalid bucket size ({bucket_size}), ignoring the bucket.")
                continue
            bucket_block_dict[bucket_size].append(word_list)


def reconstruct_shares_from_dict(mail_share_list, logger):  # pylint: disable=R0912
    """Reconstruct the emails from shares."""
    mail_data_from_file_dict = collections.defaultdict(list)
    reconstructed_mail_dict = collections.defaultdict(list)
    bucket_block_dict = collections.defaultdict(list)

    # NOTE: Assumes that shares contain the same keys and are in the same order
    for mail_share in mail_share_list:
        for key, value in mail_share.items():
            mail_data_from_file_dict[key].append(value)

    # Reconstruct shares
    for key, value in mail_data_from_file_dict.items():
        if key in (shr.YAML_STRINGS.SECRET_SHARE_BLOCK.value, shr.YAML_STRINGS.SUBJECT.value):
            reconstructed_mail_dict[key] = shr.reconstruct_shares(value, logger)
        elif key == shr.YAML_STRINGS.SECRET_SHARE_TRUNCATED_BLOCK.value:
            reconstructed_mail_dict[key] = shr.reconstruct_shares(value, logger, True)
        elif key == shr.YAML_STRINGS.SEQUENCE_NUMBER.value:
            # `value` is a list of matched sequence numbers
            if not value.count(value[0]) == len(value):
                log.warning(f"Sequence numbers are not equal: {value}")
            reconstructed_mail_dict[shr.YAML_STRINGS.SEQUENCE_NUMBER.value] = value[0]
        # Construct the bucket_key_value_dict
        elif key == shr.YAML_STRINGS.SECRET_SHARE_BUCKET_BLOCKS.value:
            reconstruct_bucket_blocks(value, bucket_block_dict)
            # Remove unused bucket sizes in list
            for bucket_size, word_list in bucket_block_dict.items():
                if word_list:
                    reconstructed_mail_dict[bucket_size] = [shr.reconstruct_shares(list(shares), log, True)
                                                            for shares in zip(*word_list)]

    return dict(reconstructed_mail_dict)


def reconstruct_mails_from_shares(paths, logger):
    """Reconstruct emails from secret shared yaml files given a specified path.

    Return a list of dictionaries containing the reconstructed mail data.
    """
    reconstructed_mail_list = []
    tmp_mail_dict_shares = {}

    for path in paths:
        directory = os.listdir(path)

        for file in directory:
            found_match = False
            with open(path + file, 'r', encoding='ascii') as yaml_file:
                mail_share_dict = yaml.safe_load(yaml_file)
                reconstructed_mail_dict = {}

                # Ignore if file or contents are invalid
                if not mail_share_dict or shr.YAML_STRINGS.UID.value not in mail_share_dict:
                    log.warning(f'File {file} does not contain uid, ignoring the file.')
                    continue

                for uid, share in tmp_mail_dict_shares.items():
                    if mail_share_dict[shr.YAML_STRINGS.UID.value] == uid:
                        share.append(mail_share_dict)
                        found_match = True

                if not found_match:
                    # Add to tmp_mail_dict_shares to find matching uid later
                    tmp_mail_dict_shares[mail_share_dict[shr.YAML_STRINGS.UID.value]] = [mail_share_dict]

    # Get the number of shares from a random mail
    num_shares = len(tmp_mail_dict_shares[random.choice(list(tmp_mail_dict_shares))])

    # Reconstruct shares from mail dictionary shares
    for uid, value in tmp_mail_dict_shares.items():
        reconstructed_mail_dict = reconstruct_shares_from_dict(value, logger)
        reconstructed_mail_list.append(reconstructed_mail_dict)
        if len(value) != num_shares:
            log.warning(f"Number of shares was different for {uid}!")

    log.debug(f"Reconstructed mail list: {reconstructed_mail_list}")

    return reconstructed_mail_list, num_shares


def construct_occurrence_array(search_index_dict):
    """Construct word occurrence string from search index dictionary.

    The occurrence string is an integer array where every integer represents a byte.
    The search index dictionary contains the sequence numbers of mails that contain
    the specific word. A `1` denotes an occurrence of the word for the email at the
    specific mail, while `0` denotes a lack thereof, and padding the remaining bits
    with trailing `0`s. E.g., if the word appears in the first and the third mail
    (in accordance with the sequence number), this function returns [160], which is
    1010 0000 in binary representation.
    """
    # NOTE: Possibly move to privmail-commons
    occurrence_list_encoding_array = [128, 64, 32, 16, 8, 4, 2, 1]
    # Above follows from: [ 2^7, 2^6, 2^5, ..., 2^0 ]

    search_index_size = search_index_dict[shr.YAML_STRINGS.NUM_OF_EMAILS.value]
    for bucket_size, bucket_words in search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value].items():
        for word, sequence_numbers in bucket_words.items():

            encoding_occurrence_list = []
            encoding_result = 0

            # Iterate through entire list of sequence_numbers
            for sequence_number in range(search_index_size):
                if sequence_number % 8 == 0 and sequence_number != 0:
                    # Store current encoding result and reset for next byte
                    encoding_occurrence_list.append(encoding_result)
                    encoding_result = 0
                if sequence_number in sequence_numbers:
                    encoding_result += occurrence_list_encoding_array[sequence_number % 8]
            encoding_occurrence_list.append(encoding_result)

            search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value][bucket_size][word] = encoding_occurrence_list

    return search_index_dict


def secret_share_index(bucket_words_dict, num_shares, logger):
    """Secret share each word and occurrance array for the search index."""
    shared_search_index_dict = {}
    for bucket_size, bucket in bucket_words_dict.items():
        shared_search_index_dict[bucket_size] = []
        for word, occurrence_array in bucket.items():
            shared_search_index_dict[bucket_size].append(
                (shr.construct_shares(word, num_shares, logger, True),
                 shr.construct_shares_from_array(occurrence_array, num_shares, logger))
            )
    return shared_search_index_dict


def construct_search_index(reconstructed_mail_dict, num_shares, index_name, logger):
    """Construct search_index file from a dictionary of mail data.

    The function expects the mail dictionary to contain the following fields:
    - sequence number
    - subject
    - uid
    Additionally, the function expects the secret shared mail data to be in the fields:
    - Secret_bucket_block
    - Secret_bucket_block_size_* (according to shr.SCHEME)
    - Secret_share_truncated_block
    Note that the secret shared block data is represented by a list of data.

    The function returns a search index representing the occurrence of each word for each mail.
    Where a '0' denotes that the word did not appear in a mail and '1' denotes that it did.
    """
    search_index_dict = {}
    word_occurrence_string_dict = collections.defaultdict(list)

    sequence_numbers = [x[shr.YAML_STRINGS.SEQUENCE_NUMBER.value] for x in reconstructed_mail_dict]

    search_index_dict[shr.YAML_STRINGS.NUM_OF_EMAILS.value] = max(sequence_numbers) + 1
    search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value] = collections.defaultdict(list)
    for mail in reconstructed_mail_dict:
        bucket_list = collections.defaultdict(list)
        for bucket_size in shr.BUCKET_SCHEME:
            if bucket_size in mail:
                bucket_list[bucket_size].append(mail[bucket_size])

        for bucket_size, bucket_words in bucket_list.items():
            flattened_word_list = list(itertools.chain(*bucket_words))

            for word in flattened_word_list:
                if bucket_size not in word_occurrence_string_dict:
                    word_occurrence_string_dict[bucket_size] = collections.defaultdict(list)
                word_occurrence_string_dict[bucket_size][word].append(mail[shr.YAML_STRINGS.
                                                                           SEQUENCE_NUMBER.value])

            search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value][bucket_size] = \
                dict(word_occurrence_string_dict[bucket_size])

    # Convert to dict from defaultdict
    search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value] = \
        dict(search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value])
    search_index_dict = construct_occurrence_array(search_index_dict)

    # Create UID for the query
    search_index_dict[shr.YAML_STRINGS.UID.value] = shr.construct_uid(shr.UID_BYTE_LEN)

    log.debug(f'Search index dict: {search_index_dict}')

    # Secret share the words and occurrance arrays
    shared_search_index_dict = secret_share_index(search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value],
                                                  num_shares, logger)

    log.debug(f'Shared search index dict: {shared_search_index_dict}')

    # Store the shares in separate search index files
    for share_index in range(num_shares):
        this_search_index_dict = {}
        this_search_index_dict[shr.YAML_STRINGS.NUM_OF_EMAILS.value] = \
            search_index_dict[shr.YAML_STRINGS.NUM_OF_EMAILS.value]
        this_search_index_dict[shr.YAML_STRINGS.UID.value] = search_index_dict[shr.YAML_STRINGS.UID.value]

        this_search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value] = {}
        for bucket_size, word_and_occurrance_list in shared_search_index_dict.items():
            this_search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value][bucket_size] = []
            for word_and_occurrance_shares in word_and_occurrance_list:
                this_search_index_dict[shr.YAML_STRINGS.INDEX_BUCKETS.value][bucket_size].append(
                    {word_and_occurrance_shares[0][share_index]: word_and_occurrance_shares[1][share_index]}
                )

        shr.generate_yaml_share_file(this_search_index_dict, shr.YAML_STRINGS.INDEX_FILE_NAME.value,
                                     share_index, index_name)

    return True


def generate_arg_parser():
    """Generate an argument parser that supports basic logLevel arguments."""
    parser = argparse.ArgumentParser(
        description="PrivMail Construct Search Indexing (CSI)")

    # Arguments
    parser.add_argument("-l", "--log", dest="logLevel", default='INFO', type=str,
                        choices=['DEBUG', 'INFO',
                                 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")
    parser.add_argument("-p", "--paths", dest="paths", type=str, nargs='*', default=argparse.SUPPRESS,
                        help="Set the mail directory paths")
    parser.add_argument("-n", "--name", dest="name", type=str, default="",
                        help="Set fixed filename for the index shares (helpful for benchmark scripts)")

    return parser.parse_args()


def main():
    """Handle input arguments and receive emails from targets defined in credentials."""
    args = generate_arg_parser()

    log.setLevel(getattr(logging, args.logLevel))

    reconstructed_mail_dict, num_shares = reconstruct_mails_from_shares(args.paths, log)

    construct_search_index(reconstructed_mail_dict, num_shares, args.name, log)


if __name__ == "__main__":
    main()
