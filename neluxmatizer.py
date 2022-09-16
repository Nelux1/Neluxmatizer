import os
from urllib import parse as urlparse
import sys
import argparse
from colorama import Back, Fore, init
from parametizer.params import parametizer
from scanners.scan import scan
from scanners.scan_sqli import sqli
from scanners.scan_xss import xss
from scanners.scan_lista import all_list
from scanners.scan_lfi import lfi
from parametizer.core.save_it import save_output
import time 
start_time = time.time()
init()

print('''\033[1;34m

    @@@@     @@@@ 
    @@@@@    @@@@ @@@@@@@@@@  @@@@      @@@@    @@@ @@@@   @@@@
    @@@@ @@  @@@@ @@@@        @@@@      @@@@    @@@   @@   @@                     
    @@@@  @@ @@@@ @@@@@@@@    @@@@      @@@@    @@@     @@@     MATIZER
    @@@@    @@@@@ @@@@        @@@@      @@@@    @@@   @@   @@   
    @@@@     @@@@ @@@@@@@@@@  @@@@@@@@  @@@@@@@@@@@ @@@@   @@@@ 

                                 by Marcos Suarez for pentesters

\033[0m''')

parser = argparse.ArgumentParser(prog="neluxmatizer.py")

parser.add_argument("-u","--url",
                    dest="url",
                    help="select url to scan",
                    action='store')
parser.add_argument("-a","--all",
                    dest="all",
                    help="Check URL all vulnerabilities.",
                    action= 'store_true' )                    
parser.add_argument("--cors",
                    dest="cors",
                    help="Check Cors vulnerability.",
                    action= 'store_true' )
parser.add_argument("--hsts",
                    dest="hsts",
                    help="Check hsts header vulnerability.",
                    action= 'store_true' )
parser.add_argument("--click",
                    dest="click",
                    help="Check Clickjacking vulnerability.",
                    action= 'store_true' )
parser.add_argument("-l",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("-w",
                    dest="word",
                    help="wordlist of payloads",
                    action= 'store' )
parser.add_argument("--xss",
                    dest="xss",
                    help="Check XSS vulnerability.",
                    action= 'store_true' )
parser.add_argument("--lfi",
                    dest="lfi",
                    help="Check LFI vulnerability.",
                    action= 'store_true' )                    
parser.add_argument("--sql",
                    dest="sql",
                    help="Check SQL vulnerability.",
                    action= 'store_true' )
parser.add_argument("--idor",
                    dest="idor",
                    help="Check IDOR parameters.",
                    action= 'store_true' )                                         
parser.add_argument("--ssrf",
                    dest="ssrf",
                    help="Check SSRF parameters.",
                    action= 'store_true' )                                         
parser.add_argument("-o",
                     dest="output", 
                     help = 'Output file name')
                                                                              
args = parser.parse_args()                                                         


   
def selector(): 
    output= os.path.join('output','domain.txt')
    url = []
    wordlist=[]
    urls_vulnerables=[]
    fname= os.path.join('output','urls_vulnerables.txt')
    c=False
    cl=False
    h=False
    x=False
    l=False
    s=False
    i=False
    sr=False
    o=False
    if args.url:
     U=args.url
     if args.hsts: 
         h=True
     if args.cors:
         c=True
     if args.click:
         cl=True
     if args.idor:
         i=True
     if args.ssrf:
         sr=True             
     if args.all:
         c=True 
         cl=True 
         h=True
         x=True
         l=True
         s=True
         i=True
         sr=True
     if args.output:
         fname= os.path.join(args.output)
         o=True
     if args.xss and not args.word:
         x=True
     if args.lfi and not args.word:       
         l=True
     if args.sql and not args.word:
         s=True                                           
     scan(U,c,cl,h,x,l,s,i,sr,output,fname,o,urls_vulnerables)
     if args.word:
         uri=[]
         parametizer(U,output) 
         with open(output, "r") as f:
             for i in f.readlines():
                 i = i.strip()
                 if i == "" or i.startswith("#"):
                     continue
                 uri.append(i)
         with open(args.word, "r") as f:
             for i in f.readlines():
                 i = i.strip()
                 if i == "" or i.startswith("#"):
                     continue
                 wordlist.append(i)                                        
         if args.xss:                       
                xss(uri,wordlist,urls_vulnerables)                 
         if args.lfi: 
                lfi(uri,wordlist,urls_vulnerables)
         if args.sql:        
                sqli(uri,wordlist,urls_vulnerables)
         if args.output:
             save_output(urls_vulnerables,fname,U)                  
    elif args.usedlist:
     if args.hsts: 
         h=True
     if args.cors:
         c=True
     if args.click:
         cl=True
     if args.idor:
         i=True
     if args.ssrf:
         sr=True             
     if args.all:
         c=True 
         cl=True 
         h=True
         x=True
         l=True
         s=True
         i=True
         sr=True
     if args.output:
         fname= os.path.join(args.output)
         o=True
     if args.xss and not args.word:
         x=True
     if args.sql and not args.word:
         s=True         
     if args.lfi and not args.word:
         l=True                                       
     with open(args.usedlist, "r") as f:
         for q in f.readlines():
             q = q.strip()
             if q == "" or q.startswith("#"):
                 continue
             url.append(q)
     if not args.word:        
         all_list(url,c,cl,h,x,l,s,i,sr,output,fname,o,urls_vulnerables)        
     if args.word:
         with open(args.word, "r") as f:
             for i in f.readlines():
                 i = i.strip()
                 if i == "" or i.startswith("#"):
                     continue
                 wordlist.append(i)
         for l in url:
             uri=[]
             print()
             print('---------------------')
             print('\033[1;32m' +l+':\033[0m')
             print('---------------------')
             print()        
             parametizer(l,output) 
             with open(output, "r") as f:
                 for i in f.readlines():
                     i = i.strip()
                     if i == "" or i.startswith("#"):
                         continue
                     uri.append(i)
             if args.xss:                        
                 xss(uri,wordlist,urls_vulnerables)
             if args.lfi:
                 lfi(uri,wordlist,urls_vulnerables)                 
             if args.sql:
                 sqli(uri,wordlist,urls_vulnerables)
             if args.output:
                 save_output(urls_vulnerables,fname,l)
if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)
            
selector()





