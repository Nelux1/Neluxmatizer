from parametizer.core import requester
from parametizer.core import extractor
from parametizer.core import save_it
from urllib.parse import unquote
from colorama import Fore
import os
import sys
import time 
start_time = time.time()


def parametizer(url,output):
    print('\033[1;33mSearch parameters:\n\033[0m')
    if os.name == 'nt':
      os.system('cls')
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"    
    retry = True
    retries = 0
    while retry == True and retries <= int(3):
             response, retry = requester.connector(url)
             retry = retry
             retries   += 1
    if response == False:
         return 
    response = unquote(response)
    
    final_uris = extractor.param_extract(response , holder='FUZZ')
    save_it.save_func(final_uris , output , url)

    print(f"\033[1;32m[+] Total urls found : {len(final_uris)}\033[1;31m")


def parametizer2(url, output):
    
    print('\033[1;33mSearch parameters:\n\033[0m')
    if os.name == 'nt':
      os.system('cls')
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"    
    retry = True
    retries = 0
    while retry == True and retries <= int(3):
             response, retry = requester.connector(url)
             retry = retry
             retries   += 1
    if response == False:
         return 
    response = unquote(response)

    final_uris = extractor.param_extract2(response)
    save_it.save_func(final_uris , output , url)

    print(f"\033[1;32m[+] Total urls found : {len(final_uris)}\033[1;31m")





    
