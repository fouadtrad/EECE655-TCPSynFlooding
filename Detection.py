from scapy.all import *
from collections import Counter
from time import localtime, strftime
import logging
import os


# Anthony
synCount = Counter()
ackCount = Counter()
logging.basicConfig(filename='traffic_analysis.log', format='%(message)s', level=logging.INFO)


# Layan
def analyze (pkt):

    #check if IP layer is present in packet
    if IP in pkt:
        protocol = pkt.getlayer(2).name

        #Only analyze packets that are destined to my specific host
        if protocol=='TCP' and pkt['IP'].dst == myIP:

            if pkt['TCP'].flags.S and pkt['TCP'].dport == port:
                src = pkt['IP'].src 
                synCount[src] += 1

            if pkt['TCP'].flags.A and pkt['TCP'].dport == port:
                src = pkt['IP'].src
                ackCount[src] += 1
                        

# Anthony/Layan
def loggingFnt():

    # Anthony
    while True:
        dateTime = strftime("%d/%m/%Y , %H:%M:%S ,", localtime())
        logString = dateTime + " Everything is normal"
        time.sleep(3.5)
        if len(synCount) > 0:
            if (synCount.most_common(1)[0][1] > 3 * ackCount[synCount.most_common(1)[0][0]])and((synCount.most_common(1)[0][1]/sum(synCount.values()))*100 > 80):
                logString = dateTime + " SYN attack detected! Attacker IP: " + str(synCount.most_common(1)[0][0]) + " No. of attempts: " + str(synCount.most_common(1)[0][1])
            
    # Layan
            elif len(synCount) > 5*len(ackCount) : #Check for half open connections 
            #else:
                logString = dateTime + " SYN attack detected! From multiple IPs "        
        logging.info(logString)
        synCount.clear()
        ackCount.clear()

# Anthony
loggingThread=threading.Thread(target=loggingFnt)
loggingThread.daemon=True
loggingThread.start()

# Fouad
os.system("cls") #Clearing the screen
s = socket.socket() # Create a socket object
myIP = get_if_addr(conf.iface) # get ip address of default interface
port = 12345 # Reserve a port for your service
s.bind((myIP, port))
s.listen()
def listen():
    def run(self):  
        Client, address = s.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))


# Anthony
listenerThread=threading.Thread(target=listen)
listenerThread.daemon=True
listenerThread.start()

print("Server is listening on {}:{}".format(myIP, port))

# Layan
# sniff on loopback (for testing on one device) and default interface (for testing from 2 devices)
sniffer = AsyncSniffer(prn=analyze, store=0, iface = ["\\Device\\NPF_Loopback", conf.iface])
sniffer.start()
while True:
    time.sleep(1)