"""Contains test for uid functions."""

import logging
import os
import yaml

import pytest

import shared as shr

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("test_input, expected_result", [(1, 4), (6, 8), (30, 40)])
def test_construct_uid_valid_input(test_input, expected_result):
    assert len(shr.construct_uid(test_input)) == expected_result


@pytest.mark.parametrize("test_input", [(-1), (1.0), ("test")])
def test_construct_uid_invalid_input(test_input):
    with pytest.raises(Exception):
        shr.construct_uid(test_input)


@pytest.mark.parametrize("test_content, test_byte_len, expected_result_1, expected_result_2",
                         [("sZV0testing", 3, "sZV0", "testing")])
def test_separate_uid_valid_input(test_content, test_byte_len, expected_result_1, expected_result_2):
    assert shr.separate_uid(test_content, test_byte_len) == (expected_result_1, expected_result_2)


@pytest.mark.parametrize("test_content, test_byte_len",
                         [(-1, 0), (1.0, 0), ({"test": 1}, 0), ("t", 6), ("xxx_TEST", 3), ("äöü§$", 3)])
def test_separate_uid_invalid_input(test_content, test_byte_len):
    with pytest.raises(Exception):
        shr.separate_uid(test_content, test_byte_len)


@pytest.mark.parametrize("test_input, expected_result",
                         [("Test Test", [('Test', [0, 1])]),
                          ("Test test", [('Test', [0]), ('test', [1])]),
                          ("This is a test.", [('This', [0]), ('is', [1]), ('a', [2]), ('test.', [3])])])
def test_separate_words_from_text_valid_input(test_input, expected_result):
    assert shr.separate_words_from_text(test_input) == expected_result


@pytest.mark.parametrize("test_input", [(0), ({"test" : 1})])
def test_separate_words_from_text_invalid_input(test_input):
    with pytest.raises(Exception):
        shr.separate_words_from_text(test_input)


@pytest.mark.parametrize("test_input, expected_result",
                         [("x" * (shr.BUCKET_SCHEME[0] - 1),
                          ("x" * (shr.BUCKET_SCHEME[0] - 1)) + shr.PADDING_CHARACTER),
                          ("", shr.PADDING_CHARACTER * shr.BUCKET_SCHEME[0])])
def test_bucket_keyword_valid_input(test_input, expected_result):
    assert shr.bucket_keyword(test_input, logger) == expected_result


@pytest.mark.parametrize("test_input", [(0), ({"bucket": 1})])
def test_bucket_keyword_invalid_input(test_input):
    with pytest.raises(Exception):
        shr.bucket_keyword(test_input, logger)


@pytest.mark.parametrize("test_input, expected_result",
                         [(0, [0, 0, 0, 0, 0, 0]),
                          (1, [128, 0, 0, 0, 0, 0]),
                          (2, [192, 0, 0, 0, 0, 0]),
                          (3, [224, 0, 0, 0, 0, 0]),
                          (4, [240, 0, 0, 0, 0, 0]),
                          (5, [248, 0, 0, 0, 0, 0]),
                          (6, [252, 0, 0, 0, 0, 0]),
                          (7, [254, 0, 0, 0, 0, 0]),
                          (8, [255, 0, 0, 0, 0, 0]),
                          (9, [255, 128, 0, 0, 0, 0]),
                          (40, [255, 255, 255, 255, 255, 0]),
                          (48, [255, 255, 255, 255, 255, 255, 0]),
                          (49, [255, 255, 255, 255, 255, 255, 128]),
                          ])
def test_create_length_mask_valid_input(test_input, expected_result):
    assert shr.create_length_mask(test_input) == expected_result


@pytest.mark.parametrize("test_input",
                         [(-1), ("invalid")])
def test_create_length_mask_invalid_input(test_input):
    with pytest.raises(Exception):
        shr.create_length_mask(test_input)


@pytest.mark.parametrize("test_modifier_arguments, test_sequence_arguments, expected_result",
                         [(["NOT", "NOT", "NOT", "NOT", "NOT"], ["OR", "OR", "OR", "OR", ""], [255, 128]),
                          (["NOT", "NOT", "NOT", "NOT"], ["OR", "OR", "OR", ""], [254]),
                          (["NOT", ""], ["AND", ""], [128]),
                          (["", ""], ["OR", ""], [64]),
                          (["", "NOT"], ["AND", ""], [32]),
                          (["", "", ""], ["AND", "OR", ""], [16]),
                          (["", "", "NOT"], ["AND", "AND", ""], [8]),
                          (["", "", "", ""], ["AND", "AND", "OR", ""], [4]),
                          (["", "", "", "NOT", ""], ["AND", "AND", "AND", "AND", ""], [2,0]),
                          (["", "", "", "", ""], ["AND", "AND", "AND", "OR", ""], [1,0]),
                          (["", ""], ["AND", ""], [0]),
                          (["", "", "", "", ""], ["AND", "AND", "AND", "AND", ""], [0,0]),
                          (["", "", "", "", "NOT"], ["AND", "AND", "AND", "AND", ""], [0,128]),
                          ])
def test_create_modifier_argument_encoding_valid_input(test_modifier_arguments, test_sequence_arguments, expected_result):
    assert shr.create_modifier_argument_encoding(test_modifier_arguments, test_sequence_arguments, logger) == \
        expected_result


@pytest.mark.parametrize("test_modifier_arguments, test_sequence_arguments",
                         [("invalid_input", ["OR", "OR", "OR", ""]),
                          (["NOT", "", "NOT", "NOT"], "invalid_input"),
                          ("invalid_input", "invalid_input"),
                          (["invalid", "NOT"], ["OR", ""]),
                          (["", "NOT"], ["invalid", ""]),
                          (["", "NOT", "", ""], ["OR", "invalid", "AND", ""])])
def test_create_modifier_argument_encoding_invalid_input(test_modifier_arguments, test_sequence_arguments):
    with pytest.raises(Exception):
        shr.create_modifier_argument_encoding(test_modifier_arguments, test_sequence_arguments, logger)


@pytest.mark.parametrize("test_input, begin_block, end_block, expected_result",
                         [("""xxxBEGINxxx\nthis is a very long string\nxxxENDxxx""",
                           "xxxBEGINxxx", "xxxENDxxx", (True, "this is a very long string")),
                           ("""xxxBEGINxxx\nthis is a very long string""",
                           "xxxBEGINxxx", "xxxENDxxx", (False, ""))])
def test_contains_scheme_valid_input(test_input, begin_block, end_block, expected_result):
    assert shr.contains_scheme(test_input, begin_block, end_block) == expected_result


@pytest.mark.parametrize("test_input, begin_block, end_block",
                         [(2, "xxxBEGINxxx", "xxxENDxxx"),
                         ("test", 2, "xxxENDxxx"),
                         ("test", "xxxBEGINxxx", 2)])
def test_contains_scheme_invalid_input(test_input, begin_block, end_block):
    with pytest.raises(Exception):
        shr.contains_scheme(test_input, begin_block, end_block)


@pytest.mark.parametrize("test_input, test_block_scheme, test_secret_shr_flag, test_start_or_end_found_flag,\
                          test_secret_shr_blocks, test_secret_shr_bucket_size, test_bucket_mode, \
                          expected_result",
                          [("BEGIN", ("BEGIN", "END"), True, True, None, 0, False, (True, True, {}, 0)),
                           ("BUCKET_START_5", ("BUCKET_START_{}", "BUCKET_END_{}"), True, True, None, 5,
                            True, (True, True, {5: []}, 5)),
                           ("some_text", ("BEGIN", "END"), False, False, None, 0, False, (False, False, {}, 0)),
                           ("some_text", ("BEGIN", "END"), False, False, None, 0, True, (False, False, {}, 0)),
                           ])
def test_handle_block_type_valid_input(test_input, test_block_scheme, test_secret_shr_flag, \
                                       test_start_or_end_found_flag, test_secret_shr_blocks, \
                                       test_secret_shr_bucket_size, test_bucket_mode, expected_result):
    assert shr.handle_block_type(test_input, test_block_scheme, test_secret_shr_flag, test_start_or_end_found_flag,
                                 test_secret_shr_blocks, test_secret_shr_bucket_size, test_bucket_mode) == \
                                 expected_result


@pytest.mark.parametrize("test_input, test_block_scheme, test_secret_shr_flag, test_start_or_end_found_flag,\
                          test_secret_shr_blocks, test_secret_shr_bucket_size, test_bucket_mode",
                          [("BEGIN", {"invalid": 1}, True, True, None, 0, False),
                           ("BUCKET_START_5", ["invalid"], True, True, None, 5, True),
                           ("BEGIN", ["BEGIN", "END"], "invalid", True, None, 0, False),
                           ("BEGIN", ("BEGIN", "END"), "invalid", True, None, 0, False),
                           ("BEGIN", ("BEGIN", "END"), True, "invalid", None, 0, False),
                           ("BEGIN", ("BEGIN", "END"), True, True, None, "invalid", False),
                           ("BEGIN", ("BEGIN", "END"), True, True, None, 0, "invalid"),
                           ("BEGIN", ("BEGIN", "END"), True, True, ["invalid"], 0, False)])
def test_handle_block_type_invalid_input(test_input, test_block_scheme, test_secret_shr_flag, \
                                       test_start_or_end_found_flag, test_secret_shr_blocks, \
                                       test_secret_shr_bucket_size, test_bucket_mode):
    with pytest.raises(Exception):
        shr.handle_block_type(test_input, test_block_scheme, test_secret_shr_flag, test_start_or_end_found_flag,
                                 test_secret_shr_blocks, test_secret_shr_bucket_size, test_bucket_mode)


@pytest.mark.parametrize("test_dict_1, test_dict_2, expected_result",
                         [({"a": [1]}, {"a": [2]}, {"a": [1, 2]}),
                          ({"a": [1]}, {"b": [2]}, {}),
                          ({}, {"a": [1]}, {"a":[1]}),
                          ({"a": [1]}, {}, {"a":[1]}),
                          ({"a": [["test", "test"]]}, {}, {"a":[["test", "test"]]}),
                          ({"a": [{"test": "test"}]}, {}, {"a":[{"test": "test"}]}),
                          ({"a": [1], "b": [3]}, {"a": [2], "b": [4]}, {"a":[1,2], "b": [3,4]}),
                          (({"a": ["text_1"]}, {"a": ["text_2"]}, {"a": ["text_1", "text_2"]}))
                         ])
def test_combine_share_dictionaries_valid_input(test_dict_1, test_dict_2, expected_result):
    assert shr.combine_share_dictionaries(test_dict_1, test_dict_2) == expected_result


@pytest.mark.parametrize("test_dict_1, test_dict_2",
                         [(-1, {}), ({}, "invalid"), ({"a": {"1": 1}}, {"a": {"2": 2}}),
                         ([{"a": 1}, {"b": 2}], {"a": 2})])
def test_combine_share_dictionaries_invalid_input(test_dict_1, test_dict_2):
    with pytest.raises(Exception):
        shr.combine_share_dictionaries(test_dict_1, test_dict_2)


@pytest.mark.parametrize("test_input",
                         [("test_files/")])
def test_generate_unique_filename_valid_input(test_input):
    filename = shr.generate_unique_filename(test_input)
    assert not os.path.exists(filename) == True
    os.rmdir(test_input)


@pytest.mark.parametrize("test_input",
                         [(-1), {}, ["test", "test"]])
def test_generate_unique_filename_invalid_input(test_input):
    with pytest.raises(Exception):
        shr.generate_unique_filename(test_input)


@pytest.mark.parametrize("test_data, test_share_name, test_share_index, test_index_name, expected_result",
                         [("some_data", "test_share", 0, "test_file.yaml", "test_share0/test_file.yaml")])
def test_generate_yaml_share_file_valid_input(test_data, test_share_name, test_share_index, test_index_name, \
                                              expected_result):
    path = test_share_name + str(test_share_index) + "/"
    if not os.path.exists(path):
        os.makedirs(path)
    shr.generate_yaml_share_file(test_data, test_share_name, test_share_index, test_index_name)
    assert os.path.exists(expected_result) == True

    with open(path + test_index_name, "r") as stream:
        assert yaml.safe_load(stream) == test_data

    os.remove(expected_result)
    os.rmdir(path)


@pytest.mark.parametrize("test_int_array, test_n, test_rand_bit_len, expected_result",
                         [([1,1], 2, 8, 2),
                          ([1,1], 3, 8, 3),
                          ([1,1], 10, 8, 10),
                          ([1], 10, 8, 10),
                          ([1,1,1,1], 10, 8, 10),
                          ([1,1,1,1,1,1,1,1], 10, 8, 10),
                         ])
def test_construct_shares_from_array_valid_input_1(test_int_array, test_n, test_rand_bit_len, expected_result):
    assert len(shr.construct_shares_from_array(test_int_array, test_n, logger, test_rand_bit_len)) == \
        expected_result


@pytest.mark.parametrize("test_int_array, test_n, test_rand_bit_len, expected_result",
                         [([1,1], 2, 8, 4),
                          ([1,1], 2, 7, 4),
                          ([1,1], 2, 6, 4),
                          ([1,1], 2, 5, 4),
                          ([1,1], 2, 4, 4),
                          ([1,1], 2, 3, 4),
                          ([1,1], 2, 2, 4),
                          ([1,1], 2, 1, 4),
                          ([1,1,1,1], 2, 8, 8),
                          ([1,1,1,1], 2, 7, 8),
                          ([1,1,1,1], 2, 6, 8),
                          ([1,1,1,1,1,1], 2, 8, 8),
                          ([1,1,1,1,1,1,1], 2, 8, 12),
                          ([1,1,1,1,1,1,1,1,1], 2, 8, 12),
                          ([1,1,1,1,1,1,1,1,1,1], 2, 8, 16)
                         ])
def test_construct_shares_from_array_valid_input_2(test_int_array, test_n, test_rand_bit_len, expected_result):
    assert len(shr.construct_shares_from_array(test_int_array, test_n, logger, test_rand_bit_len)[0]) == \
        expected_result


@pytest.mark.parametrize("test_int_array, test_n, test_rand_bit_len",
                         [([1,1], 2, 9),
                          ([1,1], 2, -1),
                          ([1,1], 2, 11),
                          ([1,1], "invalid", 8),
                          ([1,1], 0, 8),
                          ([1,1], 0, -1),
                          ([1,1], 0, -100),
                          ([1,1], 0, 100),
                         ])
def test_construct_shares_from_array_invalid_input(test_int_array, test_n, test_rand_bit_len):
    with pytest.raises(Exception):
        shr.construct_shares_from_array(test_int_array, test_n, logger, test_rand_bit_len)


@pytest.mark.parametrize("test_msg_string, test_n, test_truncate, expected_result",
                         [("input", 2, False, 2),
                          ("input", 4, False, 4),
                          ("input", 8, False, 8),
                          ("input", 2, True, 2),
                          ("input", 4, True, 4),
                          ("input", 8, True, 8),
                         ])
def test_construct_shares_valid_input(test_msg_string, test_n, test_truncate, expected_result):
    assert len(shr.construct_shares(test_msg_string, test_n, logger, test_truncate)) == \
        expected_result


@pytest.mark.parametrize("test_msg_string, test_n, test_truncate",
                         [("input", "invalid", False),
                          ("input", 1, True),
                          ("input", -1.5, True)
                         ])
def test_construct_shares_invalid_input(test_msg_string, test_n, test_truncate):
    with pytest.raises(Exception):
        shr.construct_shares(test_msg_string, test_n, logger, test_truncate)


@pytest.mark.parametrize("test_received_base64_shares, test_truncated, expected_result",
                         [(['WBZZTW8=', 'MXgpOBs='], False, "input"),
                          (['JhsWYVo=', 'BQEdCw8=', 'VTshRmg=', 'H09aWUk='], False, "input"),
                          (['DCUIDh4=', 'CwQcOhs=', 'KxwQJQ4=', 'JTMUBB8='], True, "INPUT")])
def test_reconstruct_shares_valid_input(test_received_base64_shares, test_truncated, expected_result):
    assert shr.reconstruct_shares(test_received_base64_shares, logger, test_truncated) == expected_result


@pytest.mark.parametrize("test_received_base64_shares, test_truncated",
                         [([None, None], False),
                          ("invalid", False),
                          (2, False)])
def test_reconstruct_shares_invalid_input(test_received_base64_shares, test_truncated):
    with pytest.raises(Exception):
        shr.reconstruct_shares(test_received_base64_shares, logger, test_truncated)


@pytest.mark.parametrize("test_msg_string, test_n, test_truncate, expected_result",
                         [("input", 2, False, "input"),
                          ("input", 8, False, "input"),
                          ("iNpUt", 2, False, "iNpUt"),
                          ("input", 2, True, "INPUT"),
                          ("iNpUt", 2, True, "INPUT"),
                          ("INPUT", 2, True, "INPUT"),
                          # add n 1-10, use longer string
                         ])
def test_construct_shares_reconstruct_shares_valid_input(test_msg_string, test_n, test_truncate, expected_result):
    test_shares = shr.construct_shares(test_msg_string, test_n, logger, test_truncate)
    test_result = shr.reconstruct_shares(test_shares, logger, test_truncate)
    assert test_result == expected_result
