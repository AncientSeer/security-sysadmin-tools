import os
import re
import argparse


log_pattern = re.compile(r'^(\S+) .*? "\S+ \S+ .*?" (\d{3})')

def checkerror(code:str) -> bool:
       return code.startswith(('4','5'))


def detect_anomalies(filepath:str,threshold:int) -> dict:
          hash = {}
          with open(filepath,'r') as fh:
            for line in fh:
             parsed_line = re.search(log_pattern,line)
             if not parsed_line:
                continue
             ip = parsed_line.group(1)
             code = parsed_line.group(2)
             if checkerror(code):
               if ip in hash:
                    hash[ip]+=1
               else:
                    hash[ip] = 1
          return {ip:key for ip,key in hash.items() if key>=threshold}


def main():
          parser = argparse.ArgumentParser(description='CLI tool to detect IP addresses with high 4xx/5xx error rates in server logs') 
          parser.add_argument("-f","--file",required = True, help="Path to the server log file") 
          parser.add_argument("-t","--threshold",type=int,default=3,help="Threshold for the number of errors to flag an IP address")
          args = parser.parse_args()
          if os.path.exists(args.file) !=True:
                           print('Log file not found')
                           exit(1)
          flagged = detect_anomalies(args.file,args.threshold)    
          if not flagged:
                   print('No anomalies detected')
          else: 
                for ip,key in  flagged.items():
                   print(f'ip:{ip} | Errors:{key}') 

if __name__ == '__main__':
        main()
       