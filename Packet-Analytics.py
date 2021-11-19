from scapy.all import * # Packet manipulation
import pandas as pd # Pandas - Create and Manipulate DataFrames
import numpy as np # Math Stuff (don't worry only used for one line :] )
import binascii # Binary to Ascii 
import seaborn as sns
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP


sns.set(color_codes=True)


num_of_packets_to_sniff = 100
pcap = sniff(count=num_of_packets_to_sniff)

# rdpcap returns packet list
## packetlist object can be enumerated 

ethernet_frame = pcap[9]
ip_packet = ethernet_frame.payload
segment = ip_packet.payload
data = segment.payload # Retrieve payload that comes after layer 4

# Observe that we just popped off previous layer header
print(ethernet_frame.summary())
print(ip_packet.summary())
print(segment.summary())

# Complete depiction of paket
## Achieving understanding that these are the fields will enable the ability 
## to ask the data more meaningful questions ie) type of layer 4 segment is defined in layer 3 packet


#ethernet_frame.show()
print('------------------------------------------------------------')



# Packets can be filtered on layers ie) ethernet_frame[scapy.layers.l2.Ether]
ethernet_type = type(ethernet_frame)
ip_type = type(ip_packet)
tcp_type = type(segment)
print("Ethernet",pcap[ethernet_type])
print("IP", pcap[ip_type])
print("TCP", pcap[tcp_type])

# Scapy provides this via import statements


print("UDP", pcap[UDP])
print('------------------------------------------------------------')

# Collect field names from IP/TCP/UDP (These will be columns in DF)

ip_fields = [field.name for field in IP().fields_desc]
tcp_fields = [field.name for field in TCP().fields_desc]
udp_fields = [field.name for field in UDP().fields_desc]



print("ip fields: ",ip_fields)
print("tcp fields: ",tcp_fields)
print("udp fields: ",udp_fields)


dataframe_fields = tcp_fields + ['ip_df', 'ip_mf', 'syn_flag', 'ack_flag', 'urg_flag', 'push_flag', 'fin_flag', 'reset_flag', 'time'] + ip_fields 

print('------------------------------------------------------------')

df = pd.DataFrame(columns=dataframe_fields)
for packet in pcap[IP]:
    
    # Field array for each row of DataFrame
    field_values = []
    # Add all IP fields to dataframe
    
    layer_type = type(packet[IP].payload)
    for field in tcp_fields:
        try:
            if field == 'options':
                field_values.append(len(packet[layer_type].fields[field]))
            else:
                field_values.append(packet[layer_type].fields[field])

        except:
            field_values.append(None)
    if packet[IP].flags.DF:
        field_values.append('1')
    else:
        field_values.append('0')

    if packet[IP].flags.MF:
        field_values.append('1')
    else:
        field_values.append('0')
    if TCP in packet:
        if packet[TCP].flags.S:
            field_values.append('1')
        else :
            field_values.append('0')

        if packet[TCP].flags.A:
            field_values.append('1')
        else :
            field_values.append('0')

        if packet[TCP].flags.U:
            field_values.append('1')
        else :
            field_values.append('0')

        if packet[TCP].flags.P:
            field_values.append('1')
        else :
            field_values.append('0')

        if packet[TCP].flags.F:
            field_values.append('1')
        else :
            field_values.append('0')

        if packet[TCP].flags.R:
            field_values.append('1')
        else :
            field_values.append('0')
    else: 
        field_values.append('0')
        field_values.append('0')
        field_values.append('0')
        field_values.append('0')
        field_values.append('0')
        field_values.append('0')

    field_values.append(packet.time)

    
    for field in ip_fields:
        if field == 'options':
            # Retrieving number of options defined in IP Header
            field_values.append(len(packet[IP].fields[field]))
        else:
            field_values.append(packet[IP].fields[field])
    
    
    # Append payload
    #field_values.append(len(packet[layer_type].payload))
    #field_values.append(packet[layer_type].payload.original)
    #field_values.append(binascii.hexlify(packet[layer_type].payload.original))
    # Add row to DF
    
    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
    df = pd.concat([df, df_append], axis=0)

# Reset Indexs
df = df.reset_index()

# Drop old index columns
#df = df.drop(columns=["index", "version", "ihl", "tos", "time"])
df = df[['index', 'len', 'src', 'dst', 'ip_df', 'ip_mf', 'sport', 'dport', 'syn_flag', 'ack_flag', 'urg_flag', 'push_flag', 'fin_flag', 'reset_flag',    'seq', 'ack', 'dataofs', 'reserved', 'flags',       'window', 'chksum', 'urgptr', 'options', 'time',       'version', 'ihl', 'tos', 'id', 'flags', 'frag', 'ttl', 'proto',       'chksum', 'options']]
print(df)
df.to_csv("packet.csv",sep=",")