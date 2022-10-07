
<a href='https://cafecito.app/nelux' rel='noopener' target='_blank'><img srcset='https://cdn.cafecito.app/imgs/buttons/button_6.png 1x, https://cdn.cafecito.app/imgs/buttons/button_6_2x.png 2x, https://cdn.cafecito.app/imgs/buttons/button_6_3.75x.png 3.75x' src='https://cdn.cafecito.app/imgs/buttons/button_6.png' alt='Invitame un café en cafecito.app' /></a>

# Neluxmatizer

Neluxmatizer is a tool for pentesters to scan vulnerabilities which within the scan are:

hsts, cors and clickjacking headers, search ssrf and idors parameters,  and finally scan and fuzzing xss, lfi and sql parameters. 

Installation & Usage 
Requirement: python 3.7 or higher

INSTALLATION:

    git clone https://github.com/Nelux1/Neluxmatizer.git
    pip3 -r install requirements
    ./neluxmatizer.py

EXAMPLES:
Scan all vulnerabilities in url with output:

    ./neluxmatizer.py -u url_to_scan.com -a -o my_name_output.txt
 
Scan all vulnerabilities list of url with output:
   
    ./neluxmatizer.py -l list_url_to_scan.txt -a -o my_name_output.txt
 
Scan one vulnerability in url with output:
   
    ./neluxmatizer.py -u url_to_scan.com --xss -o my_name_output.txt
 
Scan one vulnerability in list of with output:
   
    ./neluxmatizer.py -l list_url_to_scan.txt --xss -o my_name_output.txt
 
Important:


Only xss,sql and lfi can use wordlist payloads:

Scan url with default payload:
    
    ./neluxmatizer.py -u url_to_scan.com --xss -o my_name_output.txt

Scan url list with default payload:
   
    ./neluxmatizer.py -l list_url_to_scan.txt --xss -o my_name_output.txt

Scan url with payload:
   
    ./neluxmatizer.py -u url_to_scan.txt --xss -w my_payloads.txt -o my_name_output.txt

Scan url list with payload:
    
    ./neluxmatizer.py -l list_url_to_scan.txt --xss -w my_payloads.txt -o my_name_output.txt
