# Neluxmatizer

Installation & Usage 
Requirement: python 3.7 or higher

INSTALLATION:

    git clone https://github.com/Nelux1/Neluxmatizer.git
    pip3 -r install requirements
    ./neluxmatizer.py

EXAMPLES:
Scan all vulnerabilities in url with output:

    ./neluxmatizer.py -u url_to_scan.com -a -o mi_name_output.txt
 
Scan all vulnerabilities list of url with output:
   
    ./neluxmatizer.py -l list_url_to_scan.txt -a -o mi_name_output.txt
 
Scan one vulnerability in url with output:
   
    ./neluxmatizer.py -u url_to_scan.com --xss -o mi_name_output.txt
 
Scan one vulnerability in list of with output:
   
    ./neluxmatizer.py -l list_url_to_scan.txt --xss -o mi_name_output.txt
 
Important:


Only xss,sql and lfi can use wordlist payloads:

Scan url with default payload:
    
    ./neluxmatizer.py -u url_to_scan.com --xss -o mi_name_output.txt

Scan url list with default payload:
   
    ./neluxmatizer.py -l list_url_to_scan.txt --xss -o mi_name_output.txt

Scan url with payload:
   
    ./neluxmatizer.py -u url_to_scan.txt --xss -w my_payloads.txt -o mi_name_output.txt

Scan url list with payload:
    
    ./neluxmatizer.py -l list_url_to_scan.txt --xss -w my_payloads.txt -o mi_name_output.txt
