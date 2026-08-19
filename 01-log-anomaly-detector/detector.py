import os
import re

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


if __name__ == '__main__':
        if os.path.exists(r'server.log') !=True:
             print('Log file not found')
             exit(1)
        threshold = int(input('Enter threshold:\n'))     
        flagged = detect_anomalies(r'server.log',threshold)     
        for ip,key in  flagged.items():
             print(f'ip:{ip} | Errors:{key}') 