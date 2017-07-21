# Nessus-Scripts

**DISCLAIMER: This is based off of the template found here: https://community.tenable.com/docs/DOC-1251**

## Creds File
To get started you will need to set up a `creds` file for the script to pull from. This file should be in the same path as the script. It should be formatted as so:
```
SomeUsername
SomePassword
SomeServerIP
```

## Usage

The basic usage is ```python asset_upload.py <Asset-Name>```

When using this script, it will try top grab the IP addresses from a txt file with the same name as the asset. (IE `python asset_upload.py dev` will grab the IP list from  `dev.txt`)


[ip_scan]: <https://github.com/Rossmairm/AWS-scripts/tree/master/ip_scan>
[AWS-Scripts]: <https://github.com/Rossmairm/AWS-scripts>

### IP list file
Using `dev` again from teh previous example, IP list should look like this:

dev.txt
```
10.0.0.1
10.0.0.2
10.0.0.3
```
## Version
0.2

## TO DO

* Clean up`asset_upload.py`
* Add error handling
* Break out code into methods or packages

License
----

MIT

