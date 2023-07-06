
PrivMail Construct Search Index (CSI)
====================================

PrivMail Construct Search Index Script (CSI) is a Python script that constructs the search index for each word contained in a directory of email data.

The setup is tested in `Ubuntu 20.04` with `Python 3.8.5`.

## Running the Script

### Create search index

You can define the directory of the email data shares by setting the `--paths` flag. The script expects the email data to be secret shared files (e.g. the generated files of the `privmail-smtp-server`).

Use the `-h` option for getting the help text for more information.

To run CSI just simply run the `construct_search_index.py` script with the `--paths` flag as follows:

```
python3 construct_search_index.py --paths [path0] [path1] [...]
```