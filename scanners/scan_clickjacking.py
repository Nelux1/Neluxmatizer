import requests
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor
from parametizer.progress import update_progress
from colorama import Cursor,init
init()

def clickjacking(l,vulnerables_urls,threads):
 print()
 print('---------------------')
 print('\033[1;36m Testing Clickjacking: \033[0m') 
 print('---------------------')
 print()
 indice=0
 f=0
 p=0
 total=len(l) 
 
 def click_single(linea):
        nonlocal f,p          
        try:
            req=requests.get(linea,timeout=10.0) #Opens the url
            headers=req.headers 
        except URLError as e:
            for line in linea:
                linea = line.replace('http://', 'https://')
            try:    
                req=requests.get(linea,timeout=10.0)
                headers=req.headers
            except URLError:        
                print(f'\033[1;31{req.status_code} [?] open Url Error\033[0m')
                return
        except:
            p+=1
            update_progress(p,total)
            pass    
 
        try:
            if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
                    if "https://web.archive.org" not in req.url:
                     if req.status_code < 300:
                            print ('\033[1;32m[+]\033[0m ' + req.url)
                            f+=1
                            if f == 1:
                             vulnerables_urls.append('\n****************** VULNERABLE TO CLICKJACKING: *********************\n')
                            vulnerables_urls.append(linea) 
            p+=1
            update_progress(p,total)
        except:
            p+=1
            update_progress(p,total)
            pass           

 with ThreadPoolExecutor(max_workers=threads) as executor:
     for linea in l:
         executor.submit(click_single,linea)

 if f >=1:  
    print (f'\033[1;32m[+] Found [{f}] results vulnerable to Clickjacking\033[0m')
 else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()  
