#  client.py (get|put) [-p serv_port] <server> <source_file> [<dest_file>]
#  client.py [-p serv_port] <server>  

'''
This module handle all functions related to TFTP Client

(C) Duarte Ferreira & Milton Cruz, 18/08/2022
'''

import docopt
import tftp
import os
from socket import (
    socket,
    herror,
    gaierror,
    gethostbyaddr,
    gethostbyname_ex,
    AF_INET, SOCK_DGRAM,
)
# https://pypi.org/project/type-docopt/
usage ='''
Usage: client.py (get|put) [-p serv_port] <server> <source_file> [<dest_file>]
       client.py [-p serv_port] <server>

Options: 
-h --help       show help
get|put          get/put file from server [choices: <get> <put>]
-p serv_port    specify a communication port [default: 69]
server          server IP or name [type: int]
source_file     name of the source file
dest_file       name for the destination file
'''  
cmdss = '''
Commands:
    get remote_file [local_file]  - get a file from server and save it as local_file
    put local_file [remote_file]  - send a file to server and store it as remote_file
    dir                           - obtain a listing of remote files
    quit                          - exit TFTP client
'''

def client_putting(args):
    print("Sending data from ", args["<source_file>"])
    try:
        sent = tftp.put_file((args["<server>"],args["-p"]), args["<source_file>"])
        #sent = 1
        if (sent==-2):
            print("File not found.")
        elif (sent!=-1):
            print("Done. Sent "+str(sent)+" KBytes")
        else:
            print ("Server not responding...")
    except tftp.Err as e:   # Catching File not found or any other errors
        code = e.error_code
        print(tftp.ERROR_MSGS[code])

def client_getting(args, dir=0):
    if (dir==1):
        args["<source_file>"] = "dir"
        got = tftp.dir((args["<server>"],args["-p"]))
    else:
        if (args["<dest_file>"]==None):
            args["<dest_file>"]=args["<source_file>"]
        if (args["<source_file>"]==None):
            tftp.dir((args["<server>"],args["-p"]))
        else:
            print(args["-p"])
            print("Transferring data...")
            try:
                got = tftp.get_file((args["<server>"],args["-p"]),args["<source_file>"], args["<dest_file>"])
                if (got!=-1):
                    print("Done. Received "+str(got)+" blocks of 512 bytes")
                else:
                    print("Server not responding...")
            except tftp.Err as e: # Catching File not found or any other errors
                code = e.error_code
                print(tftp.ERROR_MSGS[code])
                if code == 1:
                    os.remove(args["<dest_file>"])

def interactive(args):
    try:
        with socket(AF_INET, SOCK_DGRAM) as sock:
            sock.connect((args["<server>"],args["-p"]))
            print("Exchanging files with server '",args["<server>"],"'")
        while True:
        # If we can connect that means there's a server
            print("tftp client> ",end='')
            inp = list(map(str, input().split()))
            ######## HELP #######
            try:
                if (inp[0]=="help" and inp[0]!="dir"):
                    # print("Why are we even here")
                    print(cmdss)
                elif (inp[0]=="dir"):
                    args["<source_file>"]=""
                    client_getting(args,dir=1)
                ######## QUIT #######
                elif (inp[0]=="quit"):
                    print("Exiting TFTP client...")
                    exit(1)
                ###### GET/PUT ######
                elif ((len(inp)<2 or len(inp)>3)and inp[0]=="get"):
                    print("Usage: get remotefile [localfile]")
                elif ((len(inp)<2 or len(inp)>3) and inp[0]=="put"):
                    print("Usage: put localfile [remotefile]")
                else:
                    if inp[0] == "get":
                        args["get"]=True
                        args["put"]=False
                        args["<source_file>"]=inp[1]
                        try:
                            args["<dest_file>"]=inp[2]
                        except:
                            args["<dest_file>"]=args["<source_file>"] # Same name
                        # Now we've got everything we need, let's actually get the file
                        client_getting(args)
                    elif inp[0] == "put":
                        args["put"]=True
                        args["get"]=False
                        args["<source_file>"]=inp[1]
                        try:
                            args["<dest_file>"]=inp[2]
                        except:
                            args["<dest_file>"]=args["<source_file>"] # Same name
                        # Now we've got everything we need, let's actually put the file
                        client_putting(args)
                    else:
                        print("Unknown command: '",inp[0],"'")
            except IndexError:
                print(cmdss)  
            except tftp.Err as e: # Catching File not found or any other errors
                code = e.error_code
                print(tftp.ERROR_MSGS[code])
                

    except gaierror:
        print("Unknown server: ", args["<server>"])
        return -1

if __name__ == '__main__':
    # Get args from stdin
    args = docopt.docopt(usage)
    #print(args)
    args["-p"] = int(args["-p"])
    if (args["get"]==False and args["put"]==False):
        interactive(args)
    else:
        if (args["get"]==True):
            client_getting(args)
        elif (args["put"]==True):
            client_putting(args)

