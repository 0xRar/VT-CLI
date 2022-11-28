<hr />
<p align="center">
    <img src="https://github.com/0xRar/VT-CLI/raw/main/images/logo.png" width=600px>
    <br />
    <br />
    A Basic VirusTotal CLI Script.
</p>
<hr />


## What is VT-CLI
**VT-CLI** is a [VirusTotal] command-line interface script where
you can scan/analyze suspicious links and files, developed for practice and personal use. 

the script is written based on the [vt-py] library presented by Virus Total themselves 
as the main dependency to interact with [VirusTotal REST API v3].


## Installation

- Clone the repository:
    ```
    $ git clone https://github.com/0xRar/VT-CLI.git
    ```

- Install the dependencies:
    ```
    $ pip install -r requirements.txt
    ```


> ⚠️To run the script you're going to need a virustotal account so you can get 
your api key: https://www.virustotal.com/gui/my-apikey


- And for the final step add your virustotal api key in `config/.env`:
    ```
    VT_TOKEN=YOUR_API_KEY_HERE
    ```


## Screenshots ✨📸
![image](https://user-images.githubusercontent.com/33517160/204376807-b954b062-96b7-47da-8efe-cd5f8b643909.png)


## Usage
```
options:
  
-h, --help          show this help message and exit
-an                 url to get the last analysis stats
-scan               url to scan and detect malware and other breaches
-anf                file hash[SHA-256, SHA-1, MD5] to get the last analysis stats
-scanf              file location to scan and detect malware and other breaches

Example: python vt-cli.py -an https://google.com/
```

```
$ python vt-cli.py -h
```

## Examples
- url/domain analysis:
    ```
    $ python vt-cli.py -an https://example.com/
    ```

- url/domain scanning:
    ```
    $ python vt-cli.py -scan https://example.com/
    ```

- file hash analysis:
    ```
    $ python vt-cli.py -anf 021a24e99694ff7d91a6864e1b443c8e8df5c9a415486ac359eb403d6453b46c
    ```

- file scan/analysis:
    ```
    $ python vt-cli.py -scanf ~/Desktop/test_file.exe
    ```
     **⚠️ this will submit the file to virustotal so make sure it doesn't contain private info.**

## Contributing
- make sure your code fixes a certain issue 
- add a functionality
- make the code better & matches the current code style. 

⚠️before contibuting its recommended to open up an [issue] to
discuss what you're trying to fix.

- How to contribute?
   - https://docs.github.com/en/get-started/quickstart/contributing-to-projects


## Credits
[mgmacias95](https://github.com/mgmacias95): For helping me with fixing a client error & 
helping others trying to make scripts with the [vt-py] library, just scrolling through the
issues you will see how much Marta contributed ❤.


[VirusTotal]: https://www.virustotal.com/
[VirusTotal REST API v3]: https://developers.virustotal.com/reference/overview
[vt-py]: https://github.com/VirusTotal/vt-py/ 
[issue]: https://github.com/0xRar/VT-CLI/issues
