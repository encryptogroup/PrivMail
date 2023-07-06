"""Contains common functions and constants shared among all PrivMail software."""

import secrets
import base64
import operator
import math
import functools
import os
import datetime
import itertools
import enum
import yaml


START = "-----BEGIN SECRET SHARE BLOCK Ver1.0-----"
END = "-----END SECRET SHARE BLOCK Ver1.0-----"

START_TRUNCATED = "-----BEGIN SECRET SHARE TRUNCATED BLOCK Ver1.0-----"
END_TRUNCATED = "-----END SECRET SHARE TRUNCATED BLOCK Ver1.0-----"

START_BUCKET = "-----BEGIN SECRET SHARE BUCKET SIZE {} BLOCK Ver1.0-----"
END_BUCKET = "-----END SECRET SHARE BUCKET SIZE {} BLOCK Ver1.0-----"

PADDING_CHARACTER = '*'

UID_BYTE_LEN = 6

CHAR_PER_LINE = 60

BUCKET_SCHEME = [5, 10, 15, 20]

# Based on SixBit ASCII (used by AIS)
SPECIAL_ENCODING = [
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    0,   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    42,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 42, 42, 42, 42, 42
]


SPECIAL_DECODING = [
    64,   65,  66,  67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,
    80,   81,  82,  83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,
    32,   33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,
    48,   49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63
]


class YAML_STRINGS(str, enum.Enum):  # pylint: disable=C0103
    """Names used for yaml files."""

    # UID should be part of any file containing secret shares
    UID = "uid"

    # These are part of the secret shared email
    SEQUENCE_NUMBER = "sequence_number"
    BODY = "body"

    # These are part of the aiosmtpd envelope (https://aiosmtpd.readthedocs.io/en/latest/concepts.html#envelope)
    MAILFROM = "mail_from"
    RCPTTOS = "rcpt_tos"

    # These are part of the default MIME.text mail
    FROM = "from"
    TO = "to"
    CC = "cc"
    SUBJECT = "subject"
    DATE = "date"

    SECRET_SHARE_BLOCK = "SECRET_SHARE_BLOCK"
    SECRET_SHARE_TRUNCATED_BLOCK = "SECRET_SHARE_TRUNCATED_BLOCK"
    SECRET_SHARE_BUCKET_BLOCKS = "SECRET_SHARE_BUCKET_BLOCKS"

    # These are part of the secret shared search query
    BUCKET_SCHEME = "bucket_scheme"
    NOT_MODIFIER = "not_modifiers"
    SEQUENCE_MODIFIERS = "sequence_modifiers"
    MODIFIER_CHAIN_SHARE = "MODIFIER_CHAIN_SHARE"

    KEYWORDS = "keywords"
    FIELD = "field"
    KEYWORD_BUCKET_SIZE = "keyword_bucket_size"
    KEYWORD = "KEYWORD"
    KEYWORD_BUCKETED = "KEYWORD_BUCKETED"
    KEYWORD_LENGTH_MASK = "KEYWORD_LENGTH_MASK"
    KEYWORD_TRUNCATED = "KEYWORD_TRUNCATED"

    # These are part of the secret shared search index
    INDEX_BUCKETS = "index_buckets"
    NUM_OF_EMAILS = "num_of_emails"

    # These are names of generated directories or files
    INDEX_FILE_NAME = "secret_shared_index_share_"
    QUERY_FILE_NAME = "secret_shared_query_share_"


def construct_shares(msg_string, N, logger, truncate=False):  # pylint: disable=C0103
    """Construct N secret shares from a string."""
    # Assume that msg_string contains only ascii characters and encode
    # to 7 bit values. Invalid characters are replaces with '?'.
    msg_bytes = msg_string.encode(encoding="ascii", errors="replace")

    # Convert bytes() to list of integers
    int_array = list(bytearray(msg_bytes))

    if truncate:
        logger.debug(f"Original string as integers (before truncation): {int_array}")
        # Special encoding from 7-bit ascii to 6-bits
        for index, character in enumerate(int_array):
            int_array[index] = SPECIAL_ENCODING[character]
        logger.debug(f"Original string as integers (after truncation): {int_array}")
        return construct_shares_from_array(int_array, N, logger, 6)

    logger.debug(f"Original string as integers: {int_array}")
    return construct_shares_from_array(int_array, N, logger, 7)


def construct_shares_from_array(int_array, N, logger, rand_bitlen=8):  # pylint: disable=C0103
    """Construct N secret shares from an integer array."""
    shares = [int_array]

    if not isinstance(N, int):
        raise Exception(f"Expected N to be of type in but got: {type(N)}")
    if N <= 1:
        raise Exception(f"Expected N to be of greater or equal to 2: {N}")
    if rand_bitlen > 8:
        raise Exception(f"Expected rand_bitlen to be less or equal to 8 but got: {rand_bitlen}")

    for _ in range(N - 1):
        this_share = []
        for i in range(len(int_array)):
            rand_bits = secrets.randbits(rand_bitlen)
            shares[0][i] = operator.xor(shares[0][i], rand_bits)
            this_share.append(rand_bits)
        shares.append(this_share)

    for share_num, share in enumerate(shares, start=1):
        logger.debug(f"Share ({share_num}): {share}")

    # Base64 representation
    share_bytes = [base64.b64encode(bytes(share)) for share in shares]

    for share_num, share_byte in enumerate(share_bytes, start=1):
        logger.debug(f"Share ({share_num}) as Base64: {share_byte.decode(encoding='ascii')}")

    # Decode in order to produce a string
    return [share.decode(encoding="ascii") for share in share_bytes]


def reconstruct_shares(received_base64_shares, logger, truncated=False):
    """Reconstruct the original string from the secret shares."""
    # 1. Decode from Base64
    received_shares = [
        base64.b64decode(share, validate=True)
        for share in received_base64_shares
    ]

    for share_num, share in enumerate(received_shares, start=1):
        logger.debug(f"Share ({share_num}): {share}")

    # 2. Convert bytes() to list of integers
    received_shares = [list(bytearray(share)) for share in received_shares]

    for share_num, share in enumerate(received_shares, start=1):
        logger.debug(f"Share ({share_num}): {share}")

    # 3. Combine the shares
    received_msg_as_integers = list(
        map(lambda args: functools.reduce(operator.xor, args), zip(*received_shares)))

    if truncated:
        # Decode with the special decoding
        for index, character in enumerate(received_msg_as_integers):
            received_msg_as_integers[index] = SPECIAL_DECODING[character]

    return bytes(received_msg_as_integers).decode(encoding="ascii")


def construct_uid(uid_byte_len):
    """Construct and return a random identifier of length uid_byte_len as a Base64 string."""
    try:
        if uid_byte_len < 0:
            raise Exception(f"Expected uid_byte_len to be greater than 0 but got: {uid_byte_len}")
        # 1. Construct a random uid of length uid_byte_len (bytes)
        uid = secrets.token_bytes(uid_byte_len)
        # 2. Encode into base64
        uid = base64.b64encode(uid)
        # 3. Decode in order to produce a string
        return uid.decode(encoding="ascii")
    except Exception as e:  # pylint: disable=C0103
        raise Exception(f"Construct_uid failed for an exception: {e}") from None


def separate_uid(content, uid_byte_len):
    """Return the uid and the remaining string from an input string."""
    # 1. Calculate the first x characters of string
    # Rounding it up to next greater multiple of 4
    x = 4 * math.ceil(uid_byte_len / 3)  # pylint: disable=C0103

    if len(content) < x:
        raise Exception(f"Expected content length to be a multiple of {x} but got: {len(content)}")
    # 2. Check if content contains valid b64 uid
    try:
        base64.b64decode(content[0:x])
    except Exception as e:  # pylint: disable=C0103
        raise Exception(f"b64decode was not successful: {e}") from None

    # 3. Return the first x characters of the content string and the rest separately
    return content[0:x], content[x:len(content)]


def contains_scheme(input_, begin_block, end_block):
    """Check if a multiline input_ (string) contains a specific scheme and return it as a string if true."""
    output = ""
    is_beginning = False
    is_end = False

    if not isinstance(begin_block, str) or not isinstance(end_block, str):
        raise Exception(f"Expected begin_block and end_block to be of type str but got: \
                        {type(begin_block)},{type(end_block)}")

    for line in input_.splitlines():
        if line == end_block:
            is_end = True
        if is_beginning and not is_end:
            output += line
        if line == begin_block:
            is_beginning = True
    return (True, output) if is_beginning and is_end else (False, "")


def bucket_keyword(word, logger):
    """Generate padded bucket word from input word."""
    if len(word) > BUCKET_SCHEME[-1]:
        logger.warning(f"The word \"{word[0]}\" is too long for any bucket!")
        return ""

    for max_char_len in BUCKET_SCHEME:
        if len(word) <= max_char_len:
            # Add padding to the word to hide the actual length
            padded_word = word
            while len(padded_word) < max_char_len:
                padded_word += PADDING_CHARACTER
            return padded_word

    return ""


def separate_words_from_text(text):
    """Separate distinct words from text and save their position index along with them."""
    distinct_words = {}
    truncated_msg_words = text.split()
    for position_index, word in enumerate(truncated_msg_words):
        if word not in distinct_words:
            distinct_words[word] = [position_index]
        else:
            distinct_words[word].append(position_index)
    return list(distinct_words.items())


def create_length_mask(keyword_length):
    """Construct a length mask.

    The length mask is an integer array where every integer represents a byte.
    E.g., if the length is 9, this function returns [255, 128, 0, 0, 0, 0], which
    is 1111 1111 1000 0000 00...00 in binary representation.
    """
    length_mask_helper_array = [0, 128, 192, 224, 240, 248, 252, 254, 255]
    # Above follows from: [ 0, 2^7, 2^7 + 2^6, ..., 2^7 + 2^6 + 2^5 + 2^4 + 2^3 + 2^2 + 2^1 + 2^0 ]
    int_array = []

    if keyword_length < 0:
        raise Exception(f"Expected keyword_length to be greater or equal to 0: {keyword_length}")

    while keyword_length >= 0:
        if keyword_length < 8:
            int_array.append(length_mask_helper_array[keyword_length])
            break
        int_array.append(length_mask_helper_array[8])
        # update keyword length for next byte
        keyword_length = keyword_length - 8

    # In order to avoid revealing the length, we pad everything to 6 bytes
    while len(int_array) < 6:
        int_array.append(0)

    return int_array


def generate_unique_filename(base_path):
    """Generate a unique filename."""
    if base_path[-1] != "/":
        base_path = base_path + "/"
    if not os.path.exists(base_path):
        os.makedirs(base_path)

    timestamp = datetime.datetime.now().strftime("%y%m%d-%H%M%S")
    randomtoken = secrets.token_urlsafe(6)
    filetype = "yaml"

    unique_file_name = f"{timestamp}_{randomtoken}.{filetype}"
    return base_path + unique_file_name


def generate_yaml_share_file(data, share_name, share_index, index_name=""):
    """Generate a yaml file from the given input data and share name parameters."""
    filename = f"{share_name}{share_index}/{index_name}"
    if index_name == "":
        filename = generate_unique_filename(filename)

    with open(filename, 'w', encoding='ascii') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)


def combine_share_dictionaries(dict_a, dict_b):
    """Combine two share dictionaries.

    Return a combined dictionary of two input dictionaries,
    values with the same key are stored in a list.
    """
    if not isinstance(dict_a, dict) or not isinstance(dict_b, dict):
        raise Exception(f"Expected input dictionaries to be of type dict but got: {type(dict_a)},{type(dict_b)}")

    # 1. Check if dictionary is empty
    if len(dict_a) == 0:
        return dict_b
    if len(dict_b) == 0:
        return dict_a

    # 2. Create new dictionary
    combined_dict = {}

    # 3. Copy values with the same key in the input dictionaries into combined dictionary
    for key in dict_a.keys():
        if key in dict_b.keys():
            combined_dict[key] = dict_a[key]
            combined_dict[key].append(dict_b[key][0])
        else:
            continue

    return combined_dict


def create_modifier_argument_encoding(modifier_arguments, sequence_arguments, logger):
    """Create an encoding from a list of modifier arguments.

    The encoding is an integer representing a byte. It is created by denoting the modifier arguments 'NOT/'OR' as 1
    and ''/'AND' as 0, and padding the remaining bits with trailing 0s. E.g., if the modifier arguments are
    ['NOT', 'AND', 'NOT', 'AND', ''], this function returns 160 which is 1010 0000 in binary representation.
    """
    modifier_encoding_array = [128, 64, 32, 16, 8, 4, 2, 1]
    # Above follows from: [ 2^7, 2^6, 2^5, ..., 2^0 ]
    encoding_result_list = []
    encoding_result = 0

    if not isinstance(modifier_arguments, list) or not isinstance(sequence_arguments, list):
        raise Exception(f"Expected modifier_arguments and sequence_arguments to be of type list but got: \
                          {type(modifier_arguments)}, {type(sequence_arguments)}")

    if len(modifier_arguments) != len(sequence_arguments):
        raise Exception(f"Expected modifier_arguments and sequence_arguments to be of the same length but got: \
                          {len(modifier_arguments)} != {len(sequence_arguments)}")

    # Check if the last element of the sequence arguments is empty string
    if not sequence_arguments[-1] == '':
        raise Exception(f"Expected sequence_arguments to contain an empty string as the last argument but got: \
                          {sequence_arguments[-1]}")
    # Check if the modifier_arguments are either NOT or ''
    if not all(argument in ('NOT', '') for argument in modifier_arguments):
        raise Exception(f"Expected modifier_arguments to be either 'NOT' or '' but got: {modifier_arguments}")

    # Check if the sequence_arguments are either OR or AND
    if not all(argument in ('OR', 'AND') for argument in sequence_arguments[:-1]):
        raise Exception(f"Expected modifier_arguments to be either 'OR' or 'AND' but got: {sequence_arguments}")

    # Merge and remove the last empty string
    combined_modifier_argument_list = list(itertools.chain(*zip(modifier_arguments, sequence_arguments)))[:-1]

    for index, argument in enumerate(combined_modifier_argument_list):
        if index % 8 == 0 and index != 0:
            # Store current encoding result and reset for next byte
            encoding_result_list.append(encoding_result)
            encoding_result = 0
        if argument.upper() == "NOT" or argument.upper() == "OR":
            encoding_result += modifier_encoding_array[index % 8]
    encoding_result_list.append(encoding_result)

    logger.debug(f"Combined modifier argument list: {combined_modifier_argument_list}")
    logger.debug(f"Output of argument list encoding: {encoding_result_list}")

    return encoding_result_list


def check_block_scheme(block_scheme):
    """Check for valid block_scheme."""
    if not isinstance(block_scheme, tuple):
        raise Exception(f"Expected block_scheme to be of type list but got: {type(block_scheme)}")
    if len(block_scheme) != 2:
        raise Exception(f"Expected block_scheme to be of length two but got: {len(block_scheme)}")


def handle_block_type(line, block_scheme,  # pylint: disable=R0913
                      secret_shr_flag,
                      start_or_end_found_flag,
                      secret_shr_blocks=None,
                      secret_shr_bucket_size=0,
                      bucket_mode=False):
    """Handle block data."""
    secret_shr_blocks = secret_shr_blocks or {}

    check_block_scheme(block_scheme)

    scheme_start = block_scheme[0]
    scheme_end = block_scheme[1]

    flag_arguments = [secret_shr_flag, start_or_end_found_flag, bucket_mode]
    if not all(isinstance(argument, bool) for argument in flag_arguments):
        raise Exception(f"Expected secret_shr_flag, start_or_end_found_flag and bucket_mode to be of type bool \
                          but got: {type(secret_shr_flag)}, {type(start_or_end_found_flag), {type(bucket_mode)}}")
    if not isinstance(secret_shr_blocks, dict):
        raise Exception(f"Expected secret_shr_blocks be of type dict but got: {type(secret_shr_blocks)}")
    if not isinstance(secret_shr_bucket_size, int):
        raise Exception(f"Expected secret_shr_bucket_size be of type int but got: {type(secret_shr_bucket_size)}")

    if bucket_mode:
        for bucket_size in BUCKET_SCHEME:
            if line == scheme_start.format(bucket_size):
                secret_shr_flag = True
                secret_shr_bucket_size = bucket_size
                secret_shr_blocks[bucket_size] = []
                start_or_end_found_flag = True
                break
            if line == scheme_end.format(bucket_size):
                secret_shr_flag = False
                start_or_end_found_flag = True
                break
    else:
        if line == scheme_start:
            secret_shr_flag = True
            start_or_end_found_flag = True
        if line == scheme_end:
            secret_shr_flag = False
            start_or_end_found_flag = True

    return secret_shr_flag, start_or_end_found_flag, secret_shr_blocks, secret_shr_bucket_size
