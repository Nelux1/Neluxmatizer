import requests
from urllib import parse as urlparse
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from colorama import Back, Fore, Cursor, init
from time import sleep
from concurrent.futures import ThreadPoolExecutor
init()

wordlist=[
 "user=",
 "account=",
 "number=",
 "order=",
 "no=",
 "doc=",
 "key=",
 "email=",
 "group=",
 "profile=",
 "edit=",
 "report=",
 "id="
]


def idor(l,params,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing IDOR parameters:\033[0m') 
    print('---------------------')
    print()
    found=0

    def idorp_single(linea,li):
         nonlocal found

         if li in linea:
             found= found + 1
             if found == 1:
                 params.append('\n****************** PARAMETERS TO IDOR: *********************\n') 
             print('\033[1;32m[+]\033[0m ' + linea)
             params.append(linea)

    with ThreadPoolExecutor(max_workers=threads) as executor:
       for linea in l:
          for li in wordlist:
             executor.submit(idorp_single,linea,li)

    if found >= 1:
     print (f'\033[1;32m[+] Found [{found}] IDORS parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")
     print()

