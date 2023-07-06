"""Privmail Construct Search Query (CSQ) Python script."""

import argparse
import logging
import sys

import yaml

# Import package from parent directory
sys.path.append('..')
import privmailcommons.shared as shr  # noqa

logging.basicConfig()
log = logging.getLogger('csq')


def secret_share_and_store(argument_list, num_shares):
    """Generate secret share of query and store in file.

    Returns True status if executed successfully
    otherwise returns False

    Argument list contains the following:
    - argument_list[0]: keyword arguments
    - argument_list[1]: field arguments
    - argument_list[2]: field modifiers (NOT arguments)
    - argument_list[3]: sequence share arguments
    """
    uid = shr.construct_uid(shr.UID_BYTE_LEN)
    keyword_shares = []
    length_shares = []
    truncated_keyword_shares = []
    bucketed_keyword_shares = []

    # Create keyword, truncated, keyword_length and bucketed_keyword shares
    for keyword in argument_list[0]:
        keyword_shares.append(shr.construct_shares(keyword, num_shares, log))
        truncated_keyword_shares.append(shr.construct_shares(keyword, num_shares, log, True))

        int_array = shr.create_length_mask(len(keyword))
        length_shares.append(shr.construct_shares_from_array(int_array, num_shares, log))

        bucketed_keyword = shr.bucket_keyword(keyword, log)
        bucketed_keyword_shares.append((shr.construct_shares(
            bucketed_keyword, num_shares, log, True), len(bucketed_keyword)))

    # Create encoded modifier shares
    encoded_modifier_argument_list = shr.create_modifier_argument_encoding(argument_list[2], argument_list[3], log)
    log.debug(f"Encoded modifier list: {encoded_modifier_argument_list}")

    encoded_modifier_shares = shr.construct_shares_from_array(encoded_modifier_argument_list, num_shares, log)
    log.debug(f"Encoded modifier shares: {encoded_modifier_shares}")

    for share_index in range(num_shares):
        # Generate and fill dictionary
        secret_shared_dict = {shr.YAML_STRINGS.UID.value: uid,
                              shr.YAML_STRINGS.KEYWORDS.value: [],
                              shr.YAML_STRINGS.NOT_MODIFIER.value: [],
                              shr.YAML_STRINGS.SEQUENCE_MODIFIERS.value: [],
                              shr.YAML_STRINGS.MODIFIER_CHAIN_SHARE.value: []}

        # Encoded modifier arguments
        secret_shared_dict[shr.YAML_STRINGS.MODIFIER_CHAIN_SHARE.value] = encoded_modifier_shares[share_index]

        # Field modifier arguments (NOT, '')
        for argument in argument_list[2]:
            if argument == 'NOT':
                secret_shared_dict[shr.YAML_STRINGS.NOT_MODIFIER.value].append(True)
            elif argument == '':
                secret_shared_dict[shr.YAML_STRINGS.NOT_MODIFIER.value].append(False)
            else:
                log.error(f"Expected argument to be either '' or 'NOT' but got: {argument}")
                return False

        # Sequence share arguments (AND,OR)
        for argument in argument_list[3][:-1]:
            if argument == "OR":
                secret_shared_dict[shr.YAML_STRINGS.SEQUENCE_MODIFIERS.value].append(argument)
            else:
                secret_shared_dict[shr.YAML_STRINGS.SEQUENCE_MODIFIERS.value].append("AND")

        # Field arguments (FROM, TO, NEW, ALL, ...)
        for argument in argument_list[1]:
            secret_shared_dict[shr.YAML_STRINGS.KEYWORDS.value].append(
                {shr.YAML_STRINGS.KEYWORDS.FIELD.value: argument})

        # User defined keyword arguments
        for index, keyword_share_list in enumerate(keyword_shares):
            log.debug(f'Keyword share list: {keyword_share_list}')
            # Avoid adding empty strings to file
            if keyword_share_list[0]:
                secret_share_dict_keywords = secret_shared_dict[shr.YAML_STRINGS.KEYWORDS.value]
                secret_share_dict_keywords[index][shr.YAML_STRINGS.KEYWORD.value] = \
                    keyword_shares[index][share_index]
                secret_share_dict_keywords[index][shr.YAML_STRINGS.KEYWORD_LENGTH_MASK.value] = \
                    length_shares[index][share_index]
                secret_share_dict_keywords[index][shr.YAML_STRINGS.KEYWORD_TRUNCATED.value] = \
                    truncated_keyword_shares[index][share_index]
                secret_share_dict_keywords[index][shr.YAML_STRINGS.KEYWORD_BUCKETED.value] = \
                    bucketed_keyword_shares[index][0][share_index]
                secret_share_dict_keywords[index][shr.YAML_STRINGS.KEYWORD_BUCKET_SIZE.value] = \
                    bucketed_keyword_shares[index][1]

        secret_shared_dict['bucket_scheme'] = shr.BUCKET_SCHEME

        # Generate a unique path for the new file
        filename = shr.generate_unique_filename(f"{shr.YAML_STRINGS.QUERY_FILE_NAME.value}{share_index}/")
        log.info(f'Creating secret share {share_index+1} out of {num_shares}.')

        # Write data into a yaml file of generated path
        with open(filename, 'w', encoding='ascii') as outfile:
            yaml.dump(secret_shared_dict, outfile, default_flow_style=False)

    return True


def generate_arg_parser():
    """Generate an argument parser that supports basic logLevel arguments."""
    parser = argparse.ArgumentParser(
        description="PrivMail Construct Search Query (CSQ)")

    # Arguments
    parser.add_argument("-l", "--log", dest="logLevel", default='INFO', type=str,
                        choices=['DEBUG', 'INFO',
                                 'WARNING', 'ERROR', 'CRITICAL'],
                        help="Set the logging level")

    parser.add_argument("--keywords", dest="keywords", type=str, nargs='*', default=argparse.SUPPRESS,
                        required=True, help="Set keyword search parameter. Expects four arguments.\
                        Example: Alice,Bob,'' TO,FROM,ALL '',NOT,'' OR,AND")

    parser.add_argument("--share", dest="share_num", type=int, required=True,
                        help='Set the number of shares to split the search query')

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
    # Check if --share flag is set
    if args.share_num is None:
        log.error(f"Expected share flag to be set but found: {args.share_num}")
        return False, ""

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

    # 3. Create secret shares
    if args.share_num < 2:
        log.error(f"Expected argument to be greater or equal to 2 but got: {args.share_num}")
        return False, ""

    status = secret_share_and_store(argument_list, args.share_num)
    # Check for error status
    if not status:
        return False, ""

    # 4. Construct IMAPv4 compliant search query
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


if __name__ == "__main__":
    main()
