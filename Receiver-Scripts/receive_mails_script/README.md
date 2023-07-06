
PrivMail Recipient Client Script (RCP)
====================================

PrivMail Recipient Client Script (RCP) is a Python script that reconstructs the original email from the secret shares (the subject and the body of the email).

The setup is tested in `Ubuntu 20.04` with `Python 3.8.5`.

## Running the Script

RCP supports IMAPv4 search commands (see for more information [here](https://datatracker.ietf.org/doc/html/rfc3501#section-6.4.4)).

### Configuration

Firstly, configure the incoming SMTP server by copying/renaming `credentials_example.yaml` to `credentials.yaml` and modify it for your needs. The `ADDRESS` refers to the SMTP server of the email account, while the `USERNAME` and `PASSWORD` refer to the account credentials. Set up the entries in the `credentials.yaml` for each email account (at least two).

### Search with keywords

You can define a user query by setting the `--keyword` flag. The flag expects four input arguments with the first being user keywords, the second being IMAPv4 compliant labels (e.g., `ALL`, `NEW`, `FROM`, ...), and third argument modifies the keyword (e.g., `NOT`, `''`) and finally the last one being `AND` or `OR`.

Use the `-h` option for getting the help text for more information.

To run RCP just simply run the `receive_mail.py` script with the `--keyword` flag as follows:

```
python3 receive_mail.py --keyword '',Alice,Bob ALL,FROM,NEW '',NOT,'' AND,OR
```

Additionally, omitting the `--keyword` flag will result in the reconstruction of all emails for ease of use:
```
python3 receive_mail.py
```
