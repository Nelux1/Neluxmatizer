import requests
from urllib.error import URLError, HTTPError
from parametizer.progress import update_progress
from colorama import Cursor,init
init()

headers = {"Origin": "https://evil.com"}


def cors(l,vulnerables_urls):
 print()
 print('---------------------')
 print('\033[1;36m Testing CORS: \033[0m') 
 print('---------------------')
 print()
 indice=0
 f=0
 p=0
 total=len(l) 
 while indice < len(l):
             
        linea=l[indice]

        try:
            req=requests.get(linea, headers=headers, timeout=10.0) #Opens the url
        except URLError as e:
            for line in linea:
                linea = line.replace('http://', 'https://')
            try:    
                req=requests.get(linea,timeout=10.0)
            except URLError:        
                print(f'\033[1;31{req.status_code} [?] open Url Error\033[0m')
                return
        except:
             p+=1
             update_progress(p,total)             
             indice+=1
             continue                                        
        try:
            if 'access-control-allow-origin' in req.headers:
                if 'https://evil.com' in req.headers:
                    f+=1
                    print ('\033[1;32m[+]\033[0m ' + req.url)
                    print("\x1b[1;35m[*]\033[0;m"+f" Access-Control-Allow-Origin: {req.headers['Access-Control-Allow-Origin']}")
                    if f == 1:
                     vulnerables_urls.append('\n****************** VULNERABLE TO CORS: *********************\n') 
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
    print (f'\033[1;32m[+] Found [{f}] results vulnerable to XSS\033[0m')
 else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()  
