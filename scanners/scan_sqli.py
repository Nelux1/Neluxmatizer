from concurrent.futures import ThreadPoolExecutor
import requests
from urllib import parse as urlparse
from parametizer.progress import update_progress
import random
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from colorama import Back, Fore, Cursor, init
from time import sleep
init()

wordlist=[
        "id=",
        "select=",
        "report=",
        "role=",
        "update=",
        "query=",
        "user=",
        "name=",
        "sort=",
        "where=",
        "search=",
        "params=",
        "process=",
        "row=",
        "view=",
        "table=",
        "from=",
        "sel=",
        "results=",
        "sleep=",
        "fetch=",
        "order=",
        "keyword=",
        "column=",
        "field=",
        "delete=",
        "string=",
        "number=",
        "filter="
        ]

responses=[
    "sql syntax near",
    "syntax error has occurred",
    "incorrect syntax near",
    "unexpected end of SQL command",
    "Warning: mysql_connect()",
    "Warning: mysql_query()",
    "Warning: pg_connect()",
    "Warning: mysql_fetch_array()"
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

def sqli(l,wi,urls_vulnerables,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing SQL parameters:\033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0
    p=0
    total=len(l)
    def sql_single(linea,w):
      nonlocal found,p
      
      if 'FUZZ' in linea:
         linea= linea.replace('=FUZZ',f'={w}')
      elif '=' and not 'FUZZ' in linea:
         linea= linea.replace('=',f'={w}')                         
      try:
         req= requests.get(linea,headers=headers,timeout=50)
         body= str(urlopen(linea).read()).lower()
         for x in responses:
             if x in req.text:  
                 found= found + 1
                 if found == 1:
                     urls_vulnerables.append('\n****************** PARAMETERS TO SQL: *********************\n')
                 print('\033[1;32m[+]\033[0m ' + req.url)
                 urls_vulnerables.append(linea)
         p+=1
         update_progress(p,total)       
      except:
         p+=1
         update_progress(p,total)
         pass
      linea= linea.replace(f'={w}','=FUZZ')
         
    with ThreadPoolExecutor(max_workers=threads) as executor:
     for linea in l:   
         for li in wordlist:
             if li in linea:
                 for w in wi:
                     executor.submit(sql_single,linea,w)
                     
    if found >= 1:
     print()
     print (Cursor.BACK(50) + Cursor.UP(1) +f'\033[1;32m[+] Found [{found}] SQL parameter/s"\033[0m')
     print()      
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()           


def sqli_params(l,params,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing SQLI parameters:\033[0m') 
    print('---------------------')
    print()
    found=0

    def sqlp_single():
         nonlocal found
         if li in linea:
             found= found + 1
             if found == 1:
                 params.append('\n****************** PARAMETERS TO SQLI: *********************\n')
             print('\033[1;32m[+]\033[0m ' + linea)
             params.append(linea)

    with ThreadPoolExecutor(max_workers=threads) as executor:
     for linea in l:   
         for li in wordlist:
             executor.submit(sqlp_single,linea,li)

    if found >= 1:
     print()
     print (f'\033[1;32m[+] Found [{found}] SQLI parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")
