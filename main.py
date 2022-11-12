#!/usr/bin/env python
import argparse
import json
import os
import random
import string
import sys
from pprint import pprint

import vt
from colorama import Fore
from dotenv import load_dotenv

"""
------------------------------
Virus Total CLI
By: Isa Ebrahim - 0xRar (2022)

Uses the virustotal api/module as the
main dependency.

https://virustotal.github.io/vt-py
------------------------------
"""

load_dotenv(dotenv_path="config/.env")
token = os.getenv("VT_TOKEN")
client = vt.Client(token)


def banner():
    b = Fore.BLUE
    c = Fore.CYAN
    r = Fore.RESET

    ascii = """
    {}__      _________      _____ _      _____ 
    {}\ \    / /__   __|    / ____| |    |_   _|
    {} \ \  / /   | |______| |    | |      | |  
    {}  \ \/ /    | |______| |    | |      | |  
    {}   \  /     | |      | |____| |____ _| |_ 
    {}    \/      |_|       \_____|______|_____|
    
    {}[ Coded By Isa Ebrahim (0xRar) - 2022 ]
    {}[     -h to display help message      ]
    {}
    """
    print(ascii.format(b, b, r, r, b, b, c, c, r))


# Formatting variables
dashes = "-" * 30
url_err = (
    "[-] Please Enter a URL such as: [https://example.com] and not just the domain"
)
url_err_out = Fore.RED + url_err + Fore.RESET


def url_last_analysis(url: str):
    """Get Information About a URL/DOMAIN"""

    url_id = vt.url_id(url)
    url_obj = client.get_object("/urls/{}", url_id)

    output = f"""
    First Submission Date: {url_obj.first_submission_date}
    Times Submitted: {url_obj.times_submitted}
    Content Length: {url_obj.last_http_response_content_length} Bytes
    Response Code: {url_obj.last_http_response_code}
    Stats: {url_obj.last_analysis_stats}
    """

    client.close()

    print(Fore.GREEN + "[+] Analysis Completed" + Fore.RESET)
    print("{} \n {} \n {}".format(dashes, output, dashes))


def url_scanner(url: str):
    """Scans and submit url's to detect malware and other breaches."""

    analysis = client.scan_url(url, wait_for_completion=True)
    analysis_result = analysis.to_dict()

    # pprint(analysis_result) # The output is too big and messy in the CLI, uncomment to activate

    n = 7
    rnd_str = "".join(random.choices(string.ascii_letters, k=n))

    with open(f"{rnd_str}-output.json", "w") as f:
        json_object = json.dumps(analysis_result, indent=4)
        f.write(json_object)
        f.close()

    client.close()

    print(Fore.GREEN + "[+] Analysis Completed" + Fore.RESET)
    print(Fore.GREEN + f"[+] Output saved to {rnd_str}-url_output.json" + Fore.RESET)


def file_last_analysis(hash):
    """Get Information About a File"""

    # Acceptable Hashes: SHA-256, SHA-1 or MD5
    # Examples:
    # 021a24e99694ff7d91a6864e1b443c8e8df5c9a415486ac359eb403d6453b46c
    # 84d3573747fbdf7ca822fd5a48726484c8b617e74a920dc2a68dd039b8f576fd
    # f8c974a6572fd522a64d22da3bf36db7e912ccb700bd41623ed286f1e8b0e939
    # 44d88612fea8a8f36de82e1278abb02f

    file_obj = client.get_object("/files/{}", hash)

    # extracted when possible from the file's metadata, will crash if the metadata can't be found:
    # Creation Date: {file_obj.creation_date}
    output = f"""
    First Submission Date: {file_obj.first_submission_date}
    Times Submitted: {file_obj.times_submitted}
    File Size: {file_obj.size}
    File Type: {file_obj.type_tag}
    File Type Description: {file_obj.type_description}
    Stats: {file_obj.last_analysis_stats}
    """
    client.close()

    print(Fore.GREEN + "[+] Analysis Completed" + Fore.RESET)
    print("{} \n {} \n {}".format(dashes, output, dashes))


def file_scanner(path):
    """Scans and submit file's to detect malware and other breaches."""

    with open(path, "rb") as f:
        # analysis = client.get_object("/analyses/{}", analysis.id)
        analysis = client.scan_file(f)

        while True:
            analysis = client.get_object("/analyses/{}", analysis.id)
            if analysis.status == "completed":
                break

        client.close()

    pprint(analysis.stats)
    print(Fore.GREEN + "[+] Analysis Completed" + Fore.RESET)


def main():
    """Main function to rule them all. ¯\_(ツ)_/¯"""

    if args.url_analysis:  # url analysis stats
        url_last_analysis(url=args.url_analysis)

    elif args.url_scan:  # url scanner
        url_scanner(url=args.url_scan)

    elif args.file_analysis:  # file analysis stats
        file_last_analysis(hash=args.file_analysis)

    elif args.file_scan:  # file scanner
        file_scanner(path=args.file_scan)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        epilog="\tExample: \r\npython3 " + sys.argv[0] + " -h"
    )

    parser.add_argument(
        "-an",
        dest="url_analysis",
        type=str,
        help="url to get the last analysis stats",
    )

    parser.add_argument(
        "-scan",
        dest="url_scan",
        type=str,
        help="url to scan and detect malware and other breaches",
    )

    parser.add_argument(
        "-anf",
        dest="file_analysis",
        type=str,
        help="file hash[SHA-256, SHA-1, MD5] to get the last analysis stats",
    )

    parser.add_argument(
        "-scanf",
        dest="file_scan",
        help="file location to scan and detect malware and other breaches",
    )
    args = parser.parse_args()

    banner()
    main()
