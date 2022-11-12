<hr />
<p align="center">
    <img src="https://github.com/0xRar/VT-CLI/raw/main/images/logo.png" width=400px>
    <br />
    <br />
    A VirusTotal CLI tool.
</p>
<hr />

[VirusTotal]: https://www.virustotal.com/
[VirusTotal REST API v3]: https://developers.virustotal.com/reference/overview
[vt-py]: https://github.com/VirusTotal/vt-py/ 
[issue]: https://github.com/0xRar/VT-CLI/issues

**VT-CLI** is a [VirusTotal] command-line interface tool where
you can scan/analyze suspicious links and files, developed for practice and personal use. 

the tool is written based on the [vt-py] library presented by Virus Total themselves 
as the main dependency to interact with [VirusTotal REST API v3].


## Installation
- Run the following commands to install the dependencies:

```
pip install -r requirements.txt
```


> ⚠️To run the tool you're going to need a virustotal account so you can get your api key: https://www.virustotal.com/gui/my-apikey


- And for the final step add your virustotal api key in `config/.env`:
```
VT_TOKEN=YOUR_API_KEY_HERE
```


## Usage
```
arguments:

-h, --help          show this help message and exit
-an URL_ANALYSIS   url to get the last analysis stats
-scan URL_SCAN      url to scan and detect malware and other breaches
-anf FILE_ANALYSIS  file hash[SHA-256, SHA-1, MD5] to get the last analysis stats
-scanf FILE_SCAN    file location to scan and detect malware and other breaches
```

```
python main.py -h
```

## Examples
- url/domain analysis:
```
python main.py -an https://example.com/
```

- url/domain scanning:
```
python main.py -scan https://example.com/
```

- file hash analysis:
```
python main.py -anf 021a24e99694ff7d91a6864e1b443c8e8df5c9a415486ac359eb403d6453b46c
```

## Contributing
There are no set rules for contributions just make sure your code fixes
a certain issue, add a functionality or make the code better. 

⚠️before contibuting its recommended to open up an [issue] to
discuss what you're trying to fix.

- How to contribute?
   - https://docs.github.com/en/get-started/quickstart/contributing-to-projects


## TODO
- File Scan Functionality