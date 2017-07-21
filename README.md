# Nessus-Scripts

**DISCLAIMER: This is based off of the template found here: https://community.tenable.com/docs/DOC-1251**

## Creds File
To get started you will need to set up a `creds` file for the script to pull from. It should be formatted as so:
```
SomeUsername
SomePassword
SomeServerIP
```
On line 129 you will need to decide your `creds` file path, this script is currently setup to be used it an AWS-Script. If you want to use it locally uncomment the top line and comment out the other
```
#f = open('creds', 'r') #used for running locally
f = open('../../Nessus-Scripts/creds', 'r') #used in conjunction with AWS script
```

## Usage

The basic usage is ```python asset_upload.py <Asset-Name>```

When using this script, it will try top grab the IP addresses from a txt file with the same name as the asset. (IE `python asset_upload.py dev` will grab the IP list from  `dev.txt`)

## IP Scanner usage 
If using this with the IP scanner from the [AWS-Scripts] repo, make sure the file path for the creds file is correct. Then just follow the usage instructions from the [ip_scan] README.

[ip_scan]: <https://github.com/Rossmairm/AWS-scripts/tree/master/ip_scan>
[AWS-Scripts]: <https://github.com/Rossmairm/AWS-scripts>

## Version
0.2

## TO DO

* Clean up`asset_upload.py`
* Add error handling
* Break out code into methods or packages

License
----

MIT

