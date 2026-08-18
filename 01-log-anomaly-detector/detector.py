import os

def checkerror(code:str) -> bool:
       return code.startswith(('4','5'))


def detect_anomalies(filepath:str,threshold:int) -> dict:
          hash = {}
          with open(filepath,'r') as fh:
            for line in fh:
             parsed_line = line.split(' ')
             if len(parsed_line) < 9:
                continue
             ip = parsed_line[0]
             code = parsed_line[8]
             if checkerror(code):
               if ip in hash:
                    hash[ip]+=1
               else:
                    hash[ip] = 1
          return {ip:key for ip,key in hash.items() if key>=threshold}


if __name__ == '__main__':
        if os.path.exists('server.log') !=True:
             exit()
        threshold = int(input('Enter threshold:\n'))     
        flagged = detect_anomalies('server.log',threshold)     
        for ip,key in  flagged.items():
             print(f'ip:{ip} | Errors:{key}') 