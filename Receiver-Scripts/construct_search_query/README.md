
PrivMail Construct Search Query (CSQ)
====================================

PrivMail Construct Search Query Script (CSQ) is a Python script that constructs secret shared files from user defined search queries.

The setup is tested in `Ubuntu 20.04` with `Python 3.8.5`.

## Running the Script

CSQ supports IMAPv4 search commands (see for more information [here](https://datatracker.ietf.org/doc/html/rfc3501#section-6.4.4)).

### Construct search query

You can define a user query by setting the `--keyword` flag. The flag expects four input arguments with the first being user keywords, the second being IMAPv4 compliant labels (e.g., `ALL`, `NEW`, `FROM`, ...), and third argument modifies the keyword (e.g., `NOT`, `''`) and finally the last one being `AND` or `OR`.

To secret share the search query use the `--share` flag and specify the desired number of shares.
The script will then generate the specified input as a number of secret shared files.

Use the `-h` option for getting the help text for more information.

To run CSQ just simply run the `construct_search_query.py` script with the `--share` and `--keyword` flag as follows:

```
python3 construct_search_query.py --share 2 --keyword Bob,Alice,alice@sender.com FROM,FROM,TO NOT,'',NOT OR,AND
```