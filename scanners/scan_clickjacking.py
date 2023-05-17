import requests
from urllib.error import URLError, HTTPError
from parametizer.progress import update_progress
from colorama import Cursor,init
init()

def clickjacking(l,vulnerables_urls):
 print()
 print('---------------------')
 print('\033[1;36m Testing Clickjacking: \033[0m') 
 print('---------------------')
 print()
 indice=0
 f=0
 p=0
 total=len(l) 
 while indice < len(l):
             
        linea=l[indice]

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
            indice+=1
            continue    
        try:
            if 'x-frame-options' not in headers:
                if 'content-security-policy' not in headers:
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
            indice+=1
            continue           
        indice+=1
 if f >=1:  
    print (f'\033[1;32m[+] Found [{f}] results vulnerable to Clickjacking\033[0m')
 else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()  
