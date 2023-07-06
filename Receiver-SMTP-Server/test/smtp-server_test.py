import pytest
import smtp_server as rss
import yaml
import privmailcommons.shared as shr
import os


def create_dummy_files(directory, file_name, num_files):
    for index in range(0, num_files):
        data = {}
        data[shr.YAML_STRINGS.UID.value] = "uid_" + str(index)
        data[shr.YAML_STRINGS.SEQUENCE_NUMBER.value] = index
        write_yaml(directory, file_name, index, data)


def write_yaml(directory, file_name, index, data):
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(directory + file_name + str(index) + ".yaml", 'w') as f:
        yaml.dump(data, f)


def remove_dummy_files(directory, file_name, num_files):
    for index in range(0, num_files):
        os.remove(directory + file_name + str(index) + ".yaml")
    os.rmdir(directory)


def test_reconstruct_uid_sequence_dictionary_unexpected_file_type():
    tmp_directory = "tmp_dir/"
    file_name = "test.txt"
    os.makedirs(tmp_directory)
    f = open(tmp_directory + file_name, "w")
    f.write("test")
    f.close()
    assert rss.reconstruct_uid_sequence_dictionary(tmp_directory) == {}
    os.remove(tmp_directory + file_name)
    os.rmdir(tmp_directory)


def test_reconstruct_uid_sequence_dictionary_unexpected_yaml_content():
    tmp_directory = "tmp_dir/"
    file_name = "test_"
    index = 0
    data = {"not_uid": "test"}
    write_yaml(tmp_directory, file_name, index, data)
    assert rss.reconstruct_uid_sequence_dictionary(tmp_directory) == {}
    os.remove(tmp_directory + file_name + str(index) + ".yaml")
    os.rmdir(tmp_directory)


@pytest.mark.parametrize("num_test_files, expected_result", [(1, {"uid_0": 0}),
                                                             (2, {"uid_0": 0, "uid_1": 1}),
                                                             (3, {"uid_0": 0, "uid_1": 1, "uid_2": 2})])
def test_reconstruct_uid_sequence_dictionary_unique_uid(num_test_files, expected_result):
    file_name = "test_"
    directory = "test_files/"
    create_dummy_files(directory, file_name, num_test_files)
    assert rss.reconstruct_uid_sequence_dictionary(directory) == expected_result
    remove_dummy_files(directory, file_name, num_test_files)


@pytest.mark.parametrize("test_uid_sequence_number_dict, test_uid, expected_result",
                         [({}, "uid_0", {"uid_0": 0}),
                          ({"uid_0": 0, "uid_1" : 1, "uid_3": 3}, "uid_1", {"uid_0": 0, "uid_1" : 1, "uid_3": 3}),
                          ({"uid_0": 0, "uid_1": 1}, "uid_2", {"uid_0": 0, "uid_1": 1, "uid_2": 2}),
                          ({"uid_0": 0, "uid_2": 2}, "uid_3", {"uid_0": 0, "uid_2": 2, "uid_3": 3}),
                          ({"uid_0": 0, "uid_2": 2, "uid_5": 5, "uid_10": 10, "uid_100": 100}, "uid_101",
                           {"uid_0": 0, "uid_2": 2, "uid_5": 5, "uid_10": 10, "uid_100": 100, "uid_101": 101})
                         ])
def test_update_uid_sequence_dictionary_valid_input(test_uid_sequence_number_dict, test_uid, expected_result):
    rss.update_uid_sequence_dictionary(test_uid_sequence_number_dict, test_uid)
    assert test_uid_sequence_number_dict == expected_result


# TODO: test server_start_stop
def test_start_stop_smtp_server():
    handler = rss.CustomSMTPHandler()
    server = rss.aiosmtpd.controller.Controller(handler, hostname='0.0.0.0', port="55010")
    server.start()
    server.stop()

    FILE_PATH = 'mail_data/'
    if os.path.isdir(FILE_PATH):
        os.rmdir(FILE_PATH)