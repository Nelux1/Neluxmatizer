#!/usr/bin/env python3
#
import signal
import os
from os import system
from urllib import parse as urlparse
import sys
import argparse
from colorama import Back, Fore, Cursor, Style, init
from scanners.scan_lista import all_list
from parametizer.core.headers import parse_headers
from parametizer.core.save_it import save_output
from parametizer.interrupt import signal_handler
import time 
start_time = time.time()
# Keep ANSI colors intact in Linux terminals (including Cursor terminal).
init(autoreset=False, strip=False, convert=False)



print()
print()
banners = [
 r'''
       ::::    ::: :::::::::: :::       :::    ::: :::    :::   :::   :::       ::: ::::::::::: ::::::::::: ::::::::: :::::::::: ::::::::: 
     :+:+:   :+: :+:        :+:       :+:    :+: :+:    :+:  :+:+: :+:+:    :+: :+:   :+:         :+:          :+:  :+:        :+:    :+: 
    :+:+:+  +:+ +:+        +:+       +:+    +:+  +:+  +:+  +:+ +:+:+ +:+  +:+   +:+  +:+         +:+         +:+   +:+        +:+    +:+  
   +#+ +:+ +#+ +#++:++#   +#+       +#+    +:+   +#++:+   +#+  +:+  +#+ +#++:++#++: +#+         +#+        +#+    +#++:++#   +#++:++#:    
  +#+  +#+#+# +#+        +#+       +#+    +#+  +#+  +#+  +#+       +#+ +#+     +#+ +#+         +#+       +#+     +#+        +#+    +#+    
 #+#   #+#+# #+#        #+#       #+#    #+# #+#    #+# #+#       #+# #+#     #+# #+#         #+#      #+#      #+#        #+#    #+#     
###    #### ########## ########## ########  ###    ### ###       ### ###     ### ###     ########### ######### ########## ###    ###      
 Tool For Hackers by Nelux v1.4

''',


r'''
     __   __     ______     __         __  __     __  __     __    __     ______     ______   __     ______     ______     ______    
    /\ "-.\ \   /\  ___\   /\ \       /\ \/\ \   /\_\_\_\   /\ "-./  \   /\  __ \   /\__  _\ /\ \   /\___  \   /\  ___\   /\  == \   
    \ \ \-.  \  \ \  __\   \ \ \____  \ \ \_\ \  \/_/\_\/_  \ \ \-./\ \  \ \  __ \  \/_/\ \/ \ \ \  \/_/  /__  \ \  __\   \ \  __<   
     \ \_\\"\_\  \ \_____\  \ \_____\  \ \_____\   /\_\/\_\  \ \_\ \ \_\  \ \_\ \_\    \ \_\  \ \_\   /\_____\  \ \_____\  \ \_\ \_\ 
      \/_/ \/_/   \/_____/   \/_____/   \/_____/   \/_/\/_/   \/_/  \/_/   \/_/\/_/     \/_/   \/_/   \/_____/   \/_____/   \/_/ /_/                                                                                                                                     
     
     Pentester Tool v1.4 by Nelux
''',

r'''
    ███╗   ██╗███████╗██╗     ██╗   ██╗██╗  ██╗
    ████╗  ██║██╔════╝██║     ██║   ██║╚██╗██╔╝
    ██╔██╗ ██║█████╗  ██║     ██║   ██║ ╚███╔╝ 
    ██║╚██╗██║██╔══╝  ██║     ██║   ██║ ██╔██╗ 
    ██║ ╚████║███████╗███████╗╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ MATIZER
    Turbo Pentest Tool v1.4
''',

r'''
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █ NELUXMATIZER LOADED █
    █   by n31ux / turbo  █
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
'''
]

import random

RNG = random.SystemRandom()
banner = RNG.choice(banners)
BANNER_COLORS = [
    ("\033[1;36m", "cyan"),
    ("\033[1;97m", "white"),
    ("\033[1;34m", "blue"),
]

def print_animated_banner(text, color="\033[1;36m", char_delay=0.0015, line_delay=0.03):
    out = getattr(sys, "__stdout__", sys.stdout)
    lines = text.strip("\n").split("\n")

    for line in lines:
        line = line.rstrip()
        if not line:
            out.write("\n")
            continue
        # Re-apply the chosen color on every line for terminals that reset style often.
        out.write(color)
        out.flush()
        for ch in line:
            out.write(ch)
            out.flush()
            time.sleep(char_delay)
        out.write("\033[0m\n")
        out.flush()
        time.sleep(line_delay)
    out.flush()


banner_color, _banner_color_name = RNG.choice(BANNER_COLORS)
print_animated_banner(banner, color=banner_color)
OUT = getattr(sys, "__stdout__", sys.stdout)
OUT.write("\x1b[1;35mEXIT PROGRAM WITH CRTL+C\033[0;m\n\n")
OUT.flush()

parser = argparse.ArgumentParser(prog="neluxmatizer")
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
parser.add_argument(
    "-param",
    "-p",
    dest="param_file",
    help="Endpoint list file (one URL per line); skips crawl, Wayback, headless, and param discovery. Alias: -param / -p.",
    action="store",
)
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
                    help="Session cookies for continuous authentication (format: 'name1=value1; name2=value2')",
                    action='store')
parser.add_argument("-A", "--auth",
                    dest="auth",
                    help="Authorization Bearer token for continuous authentication (format: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...')",
                    action='store')
                                                                              
args = parser.parse_args()                                                         


       
def selector():
    # Salida (-o, output/, checkpoints, PoC) respecto al directorio actual al arrancar
    work_dir = os.path.abspath(os.getcwd())
    os.environ["NELUXMATIZER_WORKDIR"] = work_dir

    output = os.path.join(work_dir, "output", "param.txt")
    url = []
    wordlist=[]
    urls_vulnerables=[]
    threads=30
    fname = os.path.join(work_dir, "output", "urls_vulnerables.txt")
    c = cl = cr = x = xe = l = s = r = rc = sr = sst = o = False
    checkpoint_manager = None
    checkpoint_id = None
    param_endpoints = None
    if args.version:
         sys.stdout.write('New version with IA 1.4\n')
         sys.stdout.flush()
         sys.stdout.write('Check the current version at https://github.com/Nelux1/Neluxmatizer.git\n')
         sys.stdout.flush()
    if args.param_file:
        if args.url or args.usedlist:
            sys.stdout.write(f'{Fore.RED}[!] Do not combine -param with -u or -l.{Fore.RESET}\n')
            sys.stdout.flush()
            sys.exit(1)
        plist = os.path.expanduser(args.param_file)
        if not os.path.exists(plist):
            sys.stdout.write(f'{Fore.RED}[!] Error: -param file not found: {args.param_file}{Fore.RESET}\n')
            sys.stdout.write(f'{Fore.YELLOW}[!] Searched path: {os.path.abspath(plist)}{Fore.RESET}\n')
            sys.stdout.flush()
            sys.exit(1)
        param_endpoints = []
        with open(plist, "r", encoding="utf-8", errors="replace") as pf:
            for line in pf:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.lower().startswith(("http://", "https://")):
                    line = "https://" + line.lstrip("/")
                param_endpoints.append(line)
        if not param_endpoints:
            sys.stdout.write(f'{Fore.RED}[!] -param file is empty or has no valid lines.{Fore.RESET}\n')
            sys.stdout.flush()
            sys.exit(1)
        url = [param_endpoints[0]]
        sys.stdout.write(
            f'{Fore.CYAN}[+] Direct endpoint mode: {len(param_endpoints)} URL(s) from {args.param_file} (no crawl / discovery){Fore.RESET}\n'
        )
        sys.stdout.flush()
        if len(param_endpoints) > 150_000:
            sys.stdout.write(
                f'{Style.BRIGHT}{Fore.RED}[!] Very large URL list: high RAM usage; split the file, lower -t, '
                f'and/or set: export NELUXMATIZER_POOL_CHUNK=2048 to cap pool batch size.{Style.RESET_ALL}\n'
            )
            sys.stdout.flush()
    elif args.url:
         url.append(str(args.url))                
    if args.usedlist and not args.param_file:
         # Expand user path and verify file existence
         list_path = os.path.expanduser(args.usedlist)
         if not os.path.exists(list_path):
             sys.stdout.write(f'{Fore.RED}[!] Error: File not found: {args.usedlist}{Fore.RESET}\n')
             sys.stdout.write(f'{Fore.YELLOW}[!] Searched path: {os.path.abspath(list_path)}{Fore.RESET}\n')
             sys.stdout.flush()
             sys.exit(1)
         
         # Read all URLs from file
         all_urls_from_file = []
         with open(list_path, "r") as f:
             for q in f.readlines():
                 q = q.strip()
                 if q == "" or q.startswith("#"):
                     continue
                 all_urls_from_file.append(q)
         
         # 🔄 CHECKPOINT SYSTEM - Will be initialized after processing all flags
         # For now, save all URLs and process them later
         url.extend(all_urls_from_file)
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
    # If -a (all) was NOT specified, but -E WAS specified, activate only those vulnerabilities
    # NOTE: -E is used to EXCLUDE when combined with -a, NOT to activate individually
    # To activate individually, use specific parameters: -click, -xss, -sql, etc.
    elif args.exceptions and not args.all:
        # If only -E was specified without -a, do nothing (maintain default state)
        # User must use specific parameters like -click, -xss, etc.
        pass 
    if args.output:
         p = os.path.expanduser(args.output)
         fname = p if os.path.isabs(p) else os.path.join(work_dir, p)
         o=True
    if args.xss and not args.word:
         x=True
    if args.sql and not args.word:
         s=True         
    if args.lfi and not args.word:
         l=True
    
    # 🔄 CHECKPOINT SYSTEM - Initialize and verify checkpoint after processing all flags
    if args.usedlist and not args.param_file:
        try:
            from parametizer.checkpoint_manager import CheckpointManager
            
            # Create complete scan parameters to identify the checkpoint
            scan_params_final = {
                'cors': c,
                'click': cl,
                'crlf': cr,
                'xss': x,
                'xxe': xe,
                'lfi': l,
                'sql': s,
                'redirect': r,
                'rce': rc,
                'ssrf': sr,
                'ssti': sst,
                'threads': threads,
                'wordlist': args.word if args.word else None,
                'oob_domain': args.oob_domain if args.oob_domain else None,
                'poc': args.poc if args.poc else False
            }
            
            list_path = os.path.expanduser(args.usedlist)
            checkpoint_manager = CheckpointManager()
            checkpoint_id = checkpoint_manager._generate_checkpoint_id(list_path, scan_params_final)
            
            # Check if checkpoint exists and load processed URLs
            if checkpoint_manager.checkpoint_exists(checkpoint_id):
                processed_urls_from_checkpoint = checkpoint_manager.get_processed_urls(checkpoint_id)
                
                if processed_urls_from_checkpoint:
                    sys.stdout.write(f'\n{Fore.YELLOW}🔄 Checkpoint found: {len(processed_urls_from_checkpoint)} URLs already processed{Fore.RESET}\n')
                    sys.stdout.flush()
                    
                    # Filter pending URLs
                    pending_urls = checkpoint_manager.filter_pending_urls(url, processed_urls_from_checkpoint)
                    
                    if pending_urls:
                        sys.stdout.write(f'{Fore.GREEN}[+] Resuming scan: {len(pending_urls)} pending URLs out of {len(url)} total{Fore.RESET}\n')
                        sys.stdout.flush()
                        url = pending_urls  # Replace list with pending URLs
                    else:
                        sys.stdout.write(f'{Fore.GREEN}✅ All URLs have been processed. Deleting checkpoint...{Fore.RESET}\n')
                        sys.stdout.flush()
                        checkpoint_manager.delete_checkpoint(checkpoint_id)
                        sys.exit(0)
                else:
                    # Empty or corrupted checkpoint, continue with all URLs
                    sys.stdout.write(f'{Fore.YELLOW}[-] Checkpoint found but empty - starting full scan{Fore.RESET}\n')
                    sys.stdout.flush()
            else:
                # No checkpoint, continue with all URLs
                sys.stdout.write(f'{Fore.GREEN}[-] No checkpoint found - starting scan from the beginning{Fore.RESET}\n')
                sys.stdout.flush()
                
        except ImportError:
            # If checkpoint manager cannot be imported, continue without checkpoint
            sys.stdout.write(f'{Fore.YELLOW}[⚠️] Checkpoint manager not available - continuing without progress saving{Fore.RESET}\n')
            sys.stdout.flush()
            checkpoint_manager = None
            checkpoint_id = None
        except Exception as e:
            # Error initializing checkpoint, continue without it
            sys.stdout.write(f'{Fore.YELLOW}[⚠️] Error initializing checkpoint: {e} - continuing without progress saving{Fore.RESET}\n')
            sys.stdout.flush()
            checkpoint_manager = None
            checkpoint_id = None
    else:
        checkpoint_manager = None
        checkpoint_id = None
                                       
    if not args.word:        
      all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth,checkpoint_manager,checkpoint_id,param_endpoints=param_endpoints)     
    if args.word:
         # Expand user path and verify file existence
         wordlist_path = os.path.expanduser(args.word)
         if not os.path.exists(wordlist_path):
             sys.stdout.write(f'{Fore.RED}[!] Error: Wordlist file not found: {args.word}{Fore.RESET}\n')
             sys.stdout.write(f'{Fore.YELLOW}[!] Searched path: {os.path.abspath(wordlist_path)}{Fore.RESET}\n')
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
           all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth,checkpoint_manager,checkpoint_id,param_endpoints=param_endpoints)
         if args.lfi:
           l=True
           all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth,checkpoint_manager,checkpoint_id,param_endpoints=param_endpoints)     
         if args.sql:
           s=True
           all_list(url,c,cl,cr,x,xe,l,s,r,rc,sr,sst,fname,o,urls_vulnerables,threads,wordlist,args.headers,args.random_agent,args.oob_domain,args.poc,args.cookies,args.auth,checkpoint_manager,checkpoint_id,param_endpoints=param_endpoints)
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
        sys.stdout.write(f"\n{Fore.YELLOW}[!] Program interrupted{Fore.RESET}\n")
        sys.stdout.flush()
        exit(0)


