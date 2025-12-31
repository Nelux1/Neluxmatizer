#!/usr/bin/env python3
#
import signal
import os
from os import system
from urllib import parse as urlparse
import sys
import argparse
from colorama import Back, Fore, init
from scanners.scan_lista import all_list
from parametizer.core.headers import parse_headers
from parametizer.core.save_it import save_output
from parametizer.interrupt import signal_handler
from colorama import Back, Fore, Cursor, init
import time 
start_time = time.time()
init()
     
sys.stdout.write("\033[1;36m"+'''

    NNN     NNNN 
    NNNN    NNNN EEEEEEEEEE LLLL      UUUU    UUU XXXX   XXXX
    NNN NN  NNNN EEE        LLLL      UUUU    UUU   XX   XX                     
    NNN  NN NNNN EEEEEEEE   LLLL      UUUU    UUU     XXX     MATIZER
    NNN    NNNNN EEE        LLLL      UUUU    UUU   XX   XX   
    NNN     NNNN EEEEEEEEEE LLLLLLLL  UUUUUUUUUUU XXXX   XXXX 

                                 by Marcos Suarez for pentesters Turbo v1.0 

'''+ '\033[0;m')
sys.stdout.flush()

sys.stdout.write("\x1b[1;35m"+'EXIT PROGRAM WITH CRTL+C'+ '\033[0;m\n')
sys.stdout.flush()
sys.stdout.write('\n')
sys.stdout.flush()

parser = argparse.ArgumentParser(prog="neluxmatizer.py")
def parse_excepciones(value):
    return value.split(",")

parser.add_argument("-u","--url",
                    dest="url",
                    help="select url to scan",
                    action='store')
parser.add_argument("-a","--all",
                    dest="all",
                    help="Check URL all vulnerabilities.",
                    action= 'store_true' )                    
parser.add_argument("-cors",
                    dest="cors",
                    help="Check Cors vulnerability.",
                    action= 'store_true' )
parser.add_argument("-v",
                    dest="version",
                    help="Check version.",
                    action= 'store_true' )
parser.add_argument("-click",
                    dest="click",
                    help="Check Clickjacking vulnerability.",
                    action= 'store_true' )
parser.add_argument("-l",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action= 'store' )
parser.add_argument("-w",
                    dest="word",
                    help="wordlist of payloads",
                    action= 'store' )
parser.add_argument("-t",
                    dest="threads",
                    help="threads",
                    action= 'store' )
parser.add_argument("-xss",
                    dest="xss",
                    help="Check XSS vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-xxe",
                    dest="xxe",
                    help="Check XXE vulnerability.",
                    action= 'store_true' )
parser.add_argument("-lfi",
                    dest="lfi",
                    help="Check LFI vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-crlf",
                    dest="crlf",
                    help="Check CRLF vulnerability.",
                    action= 'store_true' )                     
parser.add_argument("-sql",
                    dest="sql",
                    help="Check SQL vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-rce",
                    dest="rce",
                    help="Check RCE vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-redirect",
                    dest="redirect",
                    help="Check OPENREDIRECT vulnerability or params.",
                    action= 'store_true' )                                                                                
parser.add_argument("-poc", "--poc",
                    dest="poc",
                    help="Generate Proof of Concept (PoC) artifacts (HTML + screenshots)",
                    action='store_true')
parser.add_argument("-ssrf",
                    dest="ssrf",
                    help="Check SSRF vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-obd","--oob-domain",
                    dest="oob_domain",
                    help="Custom OOB domain for SSRF detection (e.g. 84z5c6.oob.red)",
                    action='store')
parser.add_argument("-ssti",
                    dest="ssti",
                    help="Check SSTI vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-E",
                    dest="exceptions",
                    help="Except vulneranility to scan",
                    type=parse_excepciones,
                    action='store')
parser.add_argument("-H", "--headers",
                    dest="headers",
                    help="Custom headers for attack requests (format: 'Header1: value1,Header2: value2')",
                    type=parse_headers,
                    action='store')
parser.add_argument("-ra", "--random-agent",
                    dest="random_agent",
                    help="Use random User-Agent for all attack requests",
                    action='store_true')
parser.add_argument("-o",
                     dest="output", 
                     help = 'Output file name')
parser.add_argument("-C", "--cookies",
                    dest="cookies",
                    help="Cookies de sesión para autenticación continua (format: 'name1=value1; name2=value2')",
                    action='store')
parser.add_argument("-A", "--auth",
                    dest="auth",
                    help="Authorization Bearer token para autenticación continua (format: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...')",
                    action='store')
                                                                              
args = parser.parse_args()                                                         


       
def selector():    
    output= os.path.join('output','param.txt')
    url = []
    wordlist=[]
    urls_vulnerables=[]
    threads=30
    fname= os.path.join('output','urls_vulnerables.txt')
    c = cl = cr = x = xe = l = s = r = rc = sr = sst = o = False
    if args.version:
         sys.stdout.write('New version 1.0\n')
         sys.stdout.flush()
         sys.stdout.write('Check the current version at https://github.com/Nelux1/Neluxmatizer.git\n')
         sys.stdout.flush()
    if args.url:
         url.append(str(args.url))                
    if args.usedlist:
         # Expandir ruta del usuario y verificar existencia del archivo
         list_path = os.path.expanduser(args.usedlist)
         if not os.path.exists(list_path):
             sys.stdout.write(f'{Fore.RED}[!] Error: No se encontró el archivo: {args.usedlist}{Fore.RESET}\n')
             sys.stdout.write(f'{Fore.YELLOW}[!] Ruta buscada: {os.path.abspath(list_path)}{Fore.RESET}\n')
             sys.stdout.flush()
             sys.exit(1)
         with open(list_path, "r") as f:
             for q in f.readlines():
                 q = q.strip()
                 if q == "" or q.startswith("#"):
                     continue
                 url.append(q)
    if args.threads:
         threads = int(args.threads)                  
    if args.cors:
         c=True
    if args.click:
         cl=True
    if args.crlf:
         cr=True  
    if args.rce:
         rc=True
    if args.redirect:
         r=True        
    if args.ssrf:
         sr=True 
    if args.ssti:
         sst=True
    if args.xxe:
         xe=True                             
    if args.all:
         c = cl = cr = x = xe = l = s = r = rc = sr = sst=True  
         if args.exceptions:          
           exceptions = args.exceptions
           if "cors" in exceptions:
                    c = False
                    sys.stdout.write(f'{exceptions}\n')
                    sys.stdout.flush()
           if "click" in exceptions :
                    cl = False
           if "crlf" in exceptions :
                    cr = False
           if "xss" in exceptions:
                    x = False 
           if "xxe" in exceptions:
                    xe = False
           if "sql" in exceptions:
                    s = False
           if "rce" in exceptions:
                    rc = False
           if "ssrf" in exceptions:
                    sr = False
           if "ssti" in exceptions :
                   sst = False
           if "redirect" in exceptions:
                    r = False
           if "lfi" in exceptions:
                    l = False
    # Si NO se especificó -a (all), pero SÍ se especificó -E, activar solo esas vulnerabilidades
    # NOTA: -E se usa para EXCLUIR cuando se combina con -a, NO para activar individualmente
    # Para activar individualmente se usan los parámetros específicos: -click, -xss, -sql, etc.
    elif args.exceptions and not args.all:
        # Si solo se especificó -E sin -a, NO hacer nada (mantener estado por defecto)
        # El usuario debe usar parámetros específicos como -click, -xss, etc.
        pass 
    if args.output:
         fname= os.path.join(args.output)
         o=True
    if args.xss and not args.word:
         x=True
    if args.sql and not args.word:
         s=True         
    if args.lfi and not args.word:
         l=True                                       
    if not args.word:        
      all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth)     
    if args.word:
         # Expandir ruta del usuario y verificar existencia del archivo
         wordlist_path = os.path.expanduser(args.word)
         if not os.path.exists(wordlist_path):
             sys.stdout.write(f'{Fore.RED}[!] Error: No se encontró el archivo de wordlist: {args.word}{Fore.RESET}\n')
             sys.stdout.write(f'{Fore.YELLOW}[!] Ruta buscada: {os.path.abspath(wordlist_path)}{Fore.RESET}\n')
             sys.stdout.flush()
             sys.exit(1)
         with open(wordlist_path, "r") as f:
             for i in f.readlines():
                 i = i.strip()
                 if i == "" or i.startswith("#"):
                     continue
                 wordlist.append(i)             
         if args.xss:
           x=True                        
           all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth)
         if args.lfi:
           l=True
           all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth)     
         if args.sql:
           s=True
           all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth)
         if args.output:
           save_output(urls_vulnerables,fname,l)
     
    if os.path.exists(output):
        os.remove(output)
    
     
if len(sys.argv) <= 1:
    sys.stdout.write('\n%s -h for help.\n' % (sys.argv[0]))
    sys.stdout.flush()
    exit(0)


if __name__ == "__main__":
    from parametizer.interrupt import setup_interrupt_handler
    setup_interrupt_handler()
    try:
        selector()
    except KeyboardInterrupt:
        sys.stdout.write(f"\n{Fore.YELLOW}[!] Programa interrumpido{Fore.RESET}\n")
        sys.stdout.flush()
        exit(0)


