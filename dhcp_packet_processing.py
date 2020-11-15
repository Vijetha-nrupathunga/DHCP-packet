
import subprocess
import shlex
import threading
import os
import pyshark
import tkinter as tk
from tkinter import *
from tkinter import messagebox


cmd="..\scripts\dhcp_reset.bat"
tshark_cmd="tshark -Y 'dhcp'"
#print(shlex.split(cmd))
#print(shlex.split(tshark_cmd))
capture_proc=subprocess.Popen(args=['tshark','-i','Ethernet','-a','duration:30','-w', 'DHCP_packet_captured.pcapng']
,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
proc_var=subprocess.Popen(args=['..\scripts\dhcp_reset.bat'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
capture_proc.wait()

class Buttons1():
    def __init__(self,master):
        self.master=master
        self.frame=Frame(self.master)
        self.b3=Button(self.master,text="DHCP packet info",command=self.display3)
        self.b3.pack()
        self.frame.pack()

    def display3(self):
        r=Tk()
        self.text=Text(r)
        self.cap=pyshark.FileCapture(input_file='C:\\SIT_Project_Module_Example\\dhcp\\DHCP_packet_captured.pcapng')
        for pkt in self.cap:
            if 'DHCP' in pkt: 
                self.text.insert(INSERT,"dstn address: ")
                self.text.insert(INSERT,str(pkt['ip'].dst))
                self.text.insert(INSERT,"\nsrc address: ")
                self.text.insert(INSERT,str(pkt.ip.src))
                self.text.insert(INSERT,"\nsniff time: ")
                self.text.insert(INSERT,str(pkt.sniff_time))
                self.text.insert(INSERT,"\nsniff timestamp: ")
                self.text.insert(INSERT,str(pkt.sniff_timestamp))
                self.text.insert(INSERT,"\nhighest layer: ")
                self.text.insert(INSERT,str(pkt.highest_layer))
                self.text.insert(INSERT,"\npacket length: ")
                self.text.insert(INSERT,str(pkt.length))
                if(pkt.dhcp.type=='1'):
                    self.text.insert(INSERT,"\nMessage from client to server")
                if(pkt.dhcp.type=='2'):
                    self.text.insert(INSERT,"\nMessage from server to client")
                if(pkt.dhcp.option_value=='07'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP release")
                elif(pkt.dhcp.option_value=='01'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP discover")
                elif(pkt.dhcp.option_value=='02'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP offer")
                elif(pkt.dhcp.option_value=='03'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP request")
                elif(pkt.dhcp.option_value=='04'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP decline")
                elif(pkt.dhcp.option_value=='05'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP acknowledgement")
                elif(pkt.dhcp.option_value=='06'):
                    self.text.insert(INSERT,"\nMessage Type:DHCP negative acknowledgement")
                if(str(pkt['ip'].dst)=='255.255.255.255'):
                    self.text.insert(INSERT,"\nMessage is broadcast")
                else:
                    self.text.insert(INSERT,"\nMessage is unicast")
                if 'option_ip_address_lease_time' in dir(pkt['dhcp']):
                    self.text.insert(INSERT,"\nlease time: ")
                    self.text.insert(INSERT,str(pkt['dhcp'].option_ip_address_lease_time))
                self.text.insert(INSERT,"\n****************************************************************\n")
        self.text.pack()
        self.cap.close()
if __name__=='__main__':
    root=Tk()
    b=Buttons1(root)
    root.mainloop()
