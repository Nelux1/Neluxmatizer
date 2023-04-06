import mechanize
import requests
from urllib import parse as urlparse
import http.cookiejar
import sys,os
import random
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from colorama import Back, Fore, Cursor, init
from time import sleep
init()

wordlist=[
        "file=",
        "document=",
        "folder=",
        "root=",
        "path=",
        "pg=",
        "style=",
        "pdf=",
        "template=",
        "php_path=",
        "doc=",
        "page=",
        "name=",
        "cat=",
        "dir=",
        "action=",
        "board=",
        "date=",
        "detail=",
        "download=",
        "prefix=",
        "include=",
        "inc=",
        "locate=",
        "show=",
        "site=",
        "type=",
        "view=",
        "content=",
        "layout=",
        "mod=",
        "conf="
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

def lfi(l,wi,urls_vulnerables):
    print()
    print('---------------------')
    print('\033[1;36m Testing LFI parameters:\033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0
    for linea in l:   
     for li in wordlist:
         if li in linea:
            for line in l:
                for w in wi:
                     if len(urls_vulnerables) == 0:
                         print(Cursor.BACK(50) + Cursor.UP(0) + "\033[46m-_-_-_-_- TESTING -_-_-_-_-\033[0m")
                         sleep(1)
                         print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;36m_-_-_-_-_   WAIT  _-_-_-_-_\033[0m")
                     if 'FUZZ' in line:
                         line= line.replace('=FUZZ',f'={w}')
                         line= line.replace(' ','%20')
                     elif '=' and not 'FUZZ' in line:
                         line= line.replace('=',f'={w}')
                         line= line.replace(' ','%20')                         
                     try:
                         req= requests.get(line,headers=headers,timeout=50)
                         body= str(urlopen(line).read()).lower()
                         if 'root:x' in body:
                             found= found + 1
                             if found == 1:
                                 urls_vulnerables.append('\n****************** VULNERABLE TO LFI: *********************\n')             
                                 print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')
                             print ('\033[1;32m[+]\033[0m ' + linea)
                             urls_vulnerables.append(linea)  
                     except:
                         continue
                     line= line.replace('%20',' ')
                     line= line.replace(f'{w}',limp)
         else:
             continue 
    if found >= 1:
     print()   
     print (f'\033[1;32m[+] Found [{found}] LFI parameter/s"\033[0m')
     print()
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')         
     print("\033[1;31m[-] No results found\033[0m")
     print()

def lfi_params(l,params):
    print()
    print('---------------------')
    print('\033[1;36m Testing LFI parameters:\033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0
    for linea in l:   
     for li in wordlist:
         if li in linea:
             found= found + 1
             if found == 1:
                 params.append('\n****************** PARAMETERS TO LFI: *********************\n')
             print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')   
             print('\033[1;32m[+]\033[0m ' + linea)
             params.append(linea)
         else:
             continue
    if found >= 1:
     print()
     print (f'\033[1;32m[+] Found [{found}] LFI parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")
