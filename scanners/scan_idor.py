import requests
from urllib import parse as urlparse
import http.cookiejar
import sys,os
import random
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
 "report="
]


user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
                            "Mozilla/3.01 (Macintosh; PPC)",
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",  
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                          ]
user_agent = random.choice (user_agents)
headers = {'User-Agent': user_agent}

def idor(l,w,urls_vulnerables,params,threads):
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
