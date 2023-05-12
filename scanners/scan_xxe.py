import requests
from lxml import etree
from parametizer.progress import update_progress
from concurrent.futures import ThreadPoolExecutor
from urllib.error import URLError, HTTPError
from colorama import Cursor, init
from time import sleep
init()

def check_xxe_vulnerability(xml_string):
    parser = etree.XMLParser(resolve_entities=False)
    is_vulnerable = False
    try:
        etree.fromstring(xml_string, parser=parser)
    except etree.XMLSyntaxError as e:
        if 'DOCTYPE' in str(e):
            print("XXE vulnerability detected")
            is_vulnerable = True
    else:
        pass
    return is_vulnerable

def xxe(l, urls_vulnerables, threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing XXE: \033[0m')
    print('---------------------')
    print()
    found = 0
    total = len(l)
    progress = 0


    def xxe_single(url):
        nonlocal found, progress
        try:
         response = requests.get(url)
        except URLError as e:
            for line in linea:
                linea = line.replace('http://', 'https://')
            try:    
                req=requests.get(linea,timeout=10.0)
                headers=req.headers
            except URLError:        
                print(f'\033[1;31{req.status_code} [?] open Url Error\033[0m')
                return
        except requests.exceptions.RequestException:
            return
            
        if "xml" not in response.headers.get("content-type"):
            progress += 1
            update_progress(progress, total)
            return

        xml_string = response.text

        # Aquí puedes usar la función check_xxe_vulnerability() del ejemplo anterior para verificar si existe una vulnerabilidad XXE en la cadena XML

        if check_xxe_vulnerability(xml_string):
            print('\033[1;32m[+]\033[0m ' + response.url)
            urls_vulnerables.append(url)
            found += 1
            if found == 1:
                urls_vulnerables.append('\n****************** VULNERABLE TO XXE: *********************\n')
                print(Cursor.BACK(50) + Cursor.UP(1) + '   ' * 80)

        progress += 1
        update_progress(progress, total)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for linea in l:
            executor.submit(xxe_single, linea)
    
    sleep(1)
    print(Cursor.BACK(50) + Cursor.UP(1) + '   ' * 80)

    if found >= 1:
        print(Cursor.BACK(50) + Cursor.UP(1) +f'\033[1;32m[+] Found [{found}] results vulnerable to XXE\033[0m')
    else:
        print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
    

