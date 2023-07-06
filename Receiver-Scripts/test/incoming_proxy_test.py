import pytest
import construct_search_index.construct_search_index as csi
import construct_search_query.construct_search_query as csq
import receive_mails_script.receive_mail as rcp
import privmailcommons.shared as shr
import logging
import os
import yaml
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("bucket_block_shares, bucket_block_dict, expected_result",
                         [([{shr.BUCKET_SCHEME[0]: ["test1"]}, {shr.BUCKET_SCHEME[0]: ["test2"]}],
                           {shr.BUCKET_SCHEME[0]: []}, {shr.BUCKET_SCHEME[0]: [["test1"], ["test2"]]}),
                          ([{shr.BUCKET_SCHEME[0]: ["test1"], shr.BUCKET_SCHEME[1]: ["test1"]},
                            {shr.BUCKET_SCHEME[0]: ["test2"], shr.BUCKET_SCHEME[1]: ["test2"]}],
                            {shr.BUCKET_SCHEME[0]: [], shr.BUCKET_SCHEME[1]: []},
                            {shr.BUCKET_SCHEME[0]: [["test1"], ["test2"]],
                             shr.BUCKET_SCHEME[1]: [["test1"], ["test2"]]}),
                           ([{shr.BUCKET_SCHEME[0]: ["test1"]}, {shr.BUCKET_SCHEME[0]-1: ["test2"]}],
                           {shr.BUCKET_SCHEME[0]: []}, {shr.BUCKET_SCHEME[0]: [["test1"]]})
                          ])
def test_reconstruct_bucket_blocks_valid_input(bucket_block_shares, bucket_block_dict, expected_result):
    csi.reconstruct_bucket_blocks(bucket_block_shares, bucket_block_dict)
    assert bucket_block_dict == expected_result


@pytest.mark.parametrize("argument_list, num_shares, expected_result",
                         [([["Name1", "Name2"], ['FROM', 'TO'], ['NOT', ''], ['OR', '']], 2, True),
                          ([["Name1", "Name2"], ['FROM', 'TO'], ['NOT', ''], ['OR', '']], 4, True),
                          ([["Name1", "Name2"], ['FROM', 'TO'], ['NOT', ''], ['OR', '']], 8, True),
                          ([["Name1", "Name2"], ['FROM', 'TO'], ['NOT', ''], ['OR', '']], 16, True),
                          ([["Name1", "Name2", "Name3"], ['FROM', 'TO', "FROM"], ['NOT', '', 'NOT'],
                            ['OR', 'AND', '']], 2, True),
                          ([["Name1"], ['FROM'], [''], ['']], 2, True)
                         ])
def test_secret_share_and_store(argument_list, num_shares, expected_result):
    assert csq.secret_share_and_store(argument_list, num_shares) == expected_result
    for index in range(0, num_shares):
        created_shared_dir = shr.YAML_STRINGS.QUERY_FILE_NAME.value+str(index) + "/"
        assert os.path.isdir(created_shared_dir) == True
        file_list = os.listdir(created_shared_dir)
        for file in file_list:
            with open(created_shared_dir+file) as f:
                created_dict = yaml.safe_load(f)
                assert (shr.YAML_STRINGS.UID.value in created_dict) == True
                assert (shr.YAML_STRINGS.KEYWORDS.value in created_dict) == True
                assert (shr.YAML_STRINGS.NOT_MODIFIER.value in created_dict) == True
                assert (shr.YAML_STRINGS.SEQUENCE_MODIFIERS.value in created_dict) == True
                assert (shr.YAML_STRINGS.MODIFIER_CHAIN_SHARE.value in created_dict) == True
                assert (shr.YAML_STRINGS.BUCKET_SCHEME.value in created_dict) == True
                assert len(created_dict[shr.YAML_STRINGS.KEYWORDS]) == len(argument_list[0])
                assert len(created_dict[shr.YAML_STRINGS.KEYWORDS]) == len(argument_list[1])
                assert len(created_dict[shr.YAML_STRINGS.NOT_MODIFIER]) == len(argument_list[2])
            os.remove(created_shared_dir+file)
        os.rmdir(created_shared_dir)


def create_mime_text(CONTENT, SUBJECT, FROM, TO):
    msg = MIMEText(CONTENT)
    msg[shr.YAML_STRINGS.FROM.value] = FROM
    msg[shr.YAML_STRINGS.TO.value] = TO
    msg[shr.YAML_STRINGS.SUBJECT.value] = SUBJECT
    return msg


@pytest.mark.parametrize("mail_dict, start, end, expected_result",
                         [({"some_uid": [("sender", "receiver", "WBZZTW8=",
                                          "start\r\nWBZZTW8=\r\nend\r\n"),
                                          ("sender", "receiver", "MXgpOBs=",
                                          "start\r\nMXgpOBs=\r\nend\r\n"),
                                        ]
                            }, "start", "end", create_mime_text('input', 'input', 'sender', 'receiver')),
                          ({"some_uid": [("sender", "receiver", "JhsWYVo=",
                                          "start\r\nJhsWYVo=\r\nend\r\n"),
                                          ("sender", "receiver", "BQEdCw8=",
                                          "start\r\nBQEdCw8=\r\nend\r\n"),
                                          ("sender", "receiver", "VTshRmg=",
                                          "start\r\nVTshRmg=\r\nend\r\n"),
                                          ("sender", "receiver", "H09aWUk=",
                                          "start\r\nH09aWUk=\r\nend\r\n")
                                        ]
                           }, "start", "end", create_mime_text('input', 'input', 'sender', 'receiver'))
                        ])
def test_reconstruct_emails(mail_dict, start, end, expected_result):

    mail_list = rcp.reconstruct_emails(mail_dict, start, end)
    for mail in mail_list:
        assert mail.as_string() == expected_result.as_string()

# TODO: Write tests for remaining functions