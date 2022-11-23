import argparse
import os
import random
import string
import sys
from pprint import pprint

import vt
from colorama import Fore, init
from dotenv import load_dotenv

"""
==================================
Virus Total CLI
By: Isa Ebrahim - 0xRar (2022)
Discord: 0xRar#4432
==================================
"""

# Formatting variables
init(autoreset=True)
dashes = "-" * 30
b = Fore.BLUE
c = Fore.CYAN
w = Fore.WHITE
g = Fore.GREEN
y = Fore.YELLOW
r = Fore.RED

completed = g + '[+] Analysis Completed'
url_err = r + '[-] The expected input is a url, something went wrong please try again.'
hash_err = r + '[-] The expected input is a [SHA-256, SHA-1 or MD5] hash, something went wrong please try again.'


def banner():
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
    print(ascii.format(b, b, w, w, b, b, c, c, w))


def url_last_analysis(url: str, client: vt.Client):
    """
    Get Information About a URL/DOMAIN
    """

    try:
        url_id = vt.url_id(url)
        url_obj = client.get_object("/urls/{}", url_id)

        output = f"""
        Analysis for: {y + url + Fore.RESET}

        First Submission Date: {url_obj.first_submission_date}
        Last Submission Date: {url_obj.last_submission_date}
        Times Submitted: {url_obj.times_submitted}
        Content Length: {url_obj.last_http_response_content_length} Bytes
        Response Code: {url_obj.last_http_response_code}
        Stats: {url_obj.last_analysis_stats}
        """

        print('\n{}\n{}\n{}'.format(dashes, output, dashes))

    except:
        print(url_err)
    
    finally:
        print(completed)


def url_scanner(url: str, client: vt.Client):
    """
    Scans and submit url's to detect malware and other breaches.
    """

    try:
        # scan's and submit the url 
        scan = client.scan_url(url, wait_for_completion=True)
        
        url_id = vt.url_id(url)
        url_obj = client.get_object("/urls/{}", url_id) 

        output = f"""
        Analysis for: {y + url + Fore.RESET}

        First Submission Date: {url_obj.first_submission_date}
        Last Submission Date: {url_obj.last_submission_date}
        Times Submitted: {url_obj.times_submitted}
        Content Length: {url_obj.last_http_response_content_length} Bytes
        Response Code: {url_obj.last_http_response_code}
        Stats: {url_obj.last_analysis_stats}
        """

        print('\n{}\n{}\n{}'.format(dashes, output, dashes))

    except:
        print(url_err)

    finally:
        print(completed)


def file_last_analysis(hash, client: vt.Client):
    """
    Get Information About a File
    """

    # Acceptable Hashes: SHA-256, SHA-1 or MD5
    # Examples:
    # 021a24e99694ff7d91a6864e1b443c8e8df5c9a415486ac359eb403d6453b46c
    # 84d3573747fbdf7ca822fd5a48726484c8b617e74a920dc2a68dd039b8f576fd
    # f8c974a6572fd522a64d22da3bf36db7e912ccb700bd41623ed286f1e8b0e939
    # 44d88612fea8a8f36de82e1278abb02f
    try: 
        hash_obj = client.get_object("/files/{}", hash)

        output = f"""
        Analysis for: {y + hash + Fore.RESET}

        First Submission Date: {hash_obj.first_submission_date}
        Last Submission Date: {hash_obj.last_submission_date}
        Times Submitted: {hash_obj.times_submitted}
        File Size: {hash_obj.size}
        File Type: {hash_obj.type_tag}
        File Type Description: {hash_obj.type_description}
        Stats: {hash_obj.last_analysis_stats}
        """

        print('\n{}\n{}\n{}'.format(dashes, output, dashes))

    except:
        print(hash_err)

    finally:
        print(completed)


# def file_scanner(path, client: vt.Client):
#     """
#     Scans and submit file's to detect malware and other breaches.
#     """

#     try:
#         with open(path, "rb") as f:
#             scan = client.scan_file(f)

#             while True:
#                 analysis = client.get_object("/analyses/{}", analysis.id)
#                 if analysis.status == "completed":
#                     break
                
#                 output = f"""
#                 Analysis for: {y + hash + Fore.RESET}

#                 First Submission Date: {hash_obj.first_submission_date}
#                 Last Submission Date: {hash_obj.last_submission_date}
#                 Times Submitted: {hash_obj.times_submitted}
#                 File Size: {hash_obj.size}
#                 File Type: {hash_obj.type_tag}
#                 File Type Description: {hash_obj.type_description}
#                 Stats: {hash_obj.last_analysis_stats}
#                 """

#                 print('\n{}\n{}\n{}'.format(dashes, output, dashes))

#     except:
#         print(hash_err)

#     finally:
#         print(completed)


def main():
    """
    Main function to rule them all. ¯\_(ツ)_/¯
    """

    load_dotenv(dotenv_path="config/.env")
    token = os.getenv("VT_TOKEN")
    client = vt.Client(token)

    if args.url_analysis:  # url analysis stats
        url_last_analysis(url=args.url_analysis, client=client)

    elif args.url_scan:  # url scanner
        url_scanner(url=args.url_scan, client=client)

    elif args.file_analysis:  # file analysis stats
        file_last_analysis(hash=args.file_analysis, client=client)

    elif args.file_scan:  # file scanner
        file_scanner(path=args.file_scan, client=client)

    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        epilog="\tExample: \r\npython " + sys.argv[0] + " -h"
    )

    parser.add_argument(
        "-an",
        "--analyze_url",
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
