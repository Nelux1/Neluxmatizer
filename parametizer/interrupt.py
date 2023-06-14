import sys,os
import signal
from colorama import Back,Fore,Cursor,init
init()


def signal_handler(signal, frame):
     print()
     print(Cursor.BACK(50) + Cursor.UP(0) + '                                                     ')
     print("\x1b[1;35m"+'NOT CLOSE?'+ '\033[0;m'+ '  ----->  '+ "\x1b[1;31m"+ ' PRESS CTRL+C AGAIN'+ '\033[0;m')
     sys.exit(0)

