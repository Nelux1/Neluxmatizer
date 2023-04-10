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
from concurrent.futures import ThreadPoolExecutor

init()


wordlist=[
        "Lmage_url=",
        "Open=",
        "callback=",
        "cgi-bin/redirect.cgi",
        "cgi-bin/redirect.cgi?",
        "checkout=",
        "checkout_url=",
        "continue=",
        "data=",
        "dest=",
        "destination=",
        "dir=",
        "domain=",
        "feed=",
        "file=",
        "file_name=",
        "file_url=",
        "folder=",
        "folder_url=",
        "forward=",
        "from_url=",
        "go=",
        "goto=",
        "host=",
        "html=",
        "image_url=",
        "img_url=",
        "load_file=",
        "load_url=",
        "login?to=",
        "login_url=",
        "logout=",
        "navigation=",
        "next=",
        "next_page=",
        "out=",
        "page=",
        "page_url=",
        "path=",
        "port=",
        "redir=",
        "redirect=",
        "redirect_to=",
        "redirect_uri=",
        "redirect_url=",
        "reference=",
        "return=",
        "returnTo=",
        "return_path=",
        "return_to=",
        "return_url=",
        "rt=",
        "rurl=",
        "show=",
        "site=",
        "target=",
        "to=",
        "uri=",
        "url=",
        "val=",
        "validate=",
        "view=",
        "window="
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

def redirect(l,wi,urls_vulnerables,threads):
    print('--------------------------------')
    print('\033[1;36m Testing REDIRECT parameters:\033[0m') 
    print('--------------------------------')
    print()
    limp=''
    found=0

    def red_single(line,w):
     nonlocal found

     if len(urls_vulnerables) == 0:
         print(Cursor.BACK(50) + Cursor.UP(0) + "\033[46m-_-_-_-_- TESTING -_-_-_-_-\033[0m")
         sleep(2)
         print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;36m_-_-_-_-_   WAIT  _-_-_-_-_\033[0m")
     
     sleep(3)
     if 'FUZZ' in line:
         line= line.replace('=FUZZ',f'={w}')
         line= line.replace(' ','%20')
     elif '=' and not 'FUZZ' in line:
         line= line.replace('=',f'={w}')
         line= line.replace(' ','%20') 

     try:
         req= requests.get(line,headers=headers,timeout=50,allow_redirects=True)
         body= str(urlopen(line).read()).lower()
         if len(req.history) >= 2:
              # Advertencia de posible vulnerabilidad de redirección abierta
              print(f"[ALERTA] Se ha detectado una posible vulnerabilidad de redirección abierta en {url}")
              print("Redirecciones:")
              for resp in req.history:
                  print(f"\t{resp.status_code}: {resp.url}")
              found= found + 1
         if req.status_code in (302,301,307,303):
             new_url=req.headers['location']
             if 'https://' in new_url or 'http://' in new_url or 'javascript:' in new_url:
                 print('posible redirect vuln Location' + req.url)
                 found= found + 1         
         if 'https://google.com' in body:
             found= found + 1
         if found == 1:
                 urls_vulnerables.append('\n****************** VULNERABLE TO OPENREDIRECT: *********************\n')             
                 print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')
         print ('\033[1;32m[+]\033[0m ' + req.url)    
         urls_vulnerables.append(linea)          
     except:
         pass
     line= line.replace('%20',' ')
     line= line.replace(f'{w}',limp)

    with ThreadPoolExecutor(max_workers=threads) as executor:            
     for linea in l:      
         for li in wordlist:
            if li in linea:
             for line in l:
                 for w in wi:
                     executor.submit(red_single,line,w)

    if found >= 1:
     print()   
     print (f'\033[1;32m[+] Found [{found}] REDIRECT parameter/s"\033[0m')
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')   
     print("\033[1;31m[-] No results found\033[0m")
     print()

def redirect_params(l,params,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing REDIRECT parameters:\033[0m') 
    print('---------------------')
    print()  
    found=0

    def redp_single(linea,li):
     nonlocal found

     if li in linea:
             found= found + 1
             if found == 1:
                 params.append('\n****************** PARAMETERS TO REDIRECT: *********************\n') 
             print('\033[1;32m[+]\033[0m ' + linea)
             params.append(linea)
         
    with ThreadPoolExecutor(max_workers=threads) as executor:
         for linea in l: 
             for li in wordlist:
                 executor.submit(redp_single,linea,li)
                 
    if found >= 1:
     print()
     print (f'\033[1;32m[+] Found [{found}] REDIRECT parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")

