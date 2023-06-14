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

def lfi(l,wi,urls_vulnerables,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing LFI parameters:\033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0
    p=0
    total=len(l)
    def lfi_single(line,w):
     nonlocal found,p
     
     if 'FUZZ' in line:
         line= line.replace('=FUZZ',f'={w}')
         line= line.replace(' ','%20')
     elif '=' and not 'FUZZ' in line:
         line= line.replace('=',f'={w}')
         line= line.replace(' ','%20')  
                                
     try:
          req= requests.get(line,timeout=50)
          body= str(urlopen(line).read()).lower()
          if 'root:x' in body:
              found= found + 1
              if found == 1:
                 urls_vulnerables.append('\n****************** VULNERABLE TO LFI: *********************\n')             
              print ('\033[1;32m[+]\033[0m ' + req.url, end='\n')
              urls_vulnerables.append(linea)  
          p+=1
          update_progress(p, total)         
     except:
         p+=1
         update_progress(p,total)
         pass
     
     line= line.replace('%20',' ')
     line= line.replace(f'{w}',limp)

      
    with ThreadPoolExecutor(max_workers=threads) as executor:
     for linea in l:   
         for li in wordlist:
             if li in linea:
                 for w in wi:
                         executor.submit(lfi_single,linea,w)   

    if found >= 1:
     print()   
     print (Cursor.BACK(50) + Cursor.UP(1) +f'\033[1;32m[+] Found [{found}] LFI parameter/s"\033[0m')
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()

def lfi_params(l,params,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing LFI parameters:\033[0m') 
    print('---------------------')
    print()
    found=0
    
    def lfip_single(linea,li):
         nonlocal found
         if li in linea:
             found= found + 1
             if found == 1:
                 params.append('\n****************** PARAMETERS TO LFI: *********************\n')
             print('\033[1;32m[+]\033[0m ' + linea)
             params.append(linea)

    with ThreadPoolExecutor(max_workers=threads) as executor:
     for linea in l:   
         for li in wordlist:
             executor.submit(lfip_single,linea,li)   


    if found >= 1:
     print()
     print (f'\033[1;32m[+] Found [{found}] LFI parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")
