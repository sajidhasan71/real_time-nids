import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import sklearn
plt.rcParams.update({'figure.max_open_warning': 0})

# Importing the dataset
dataset = pd.read_csv('merged.csv')
x = dataset.iloc[:, :].values
x_view = pd.DataFrame(x)
rows = len(x)

class Session_Master:
    def __init__(self,src_ip,dst_ip,start_frame):
        self.server_ip = src_ip
        self.client_ip = dst_ip
        self.start_frame_no = start_frame
        self.session_count = 1
        self.packet_count = 0
        self.mf_count = 0
        self.df_count = 0
        self.push_count = 0
        self.urg_count = 0
        self.total_len = 0
        self.request_count = 0
        self.resp_success = 0
        self.resp_non_success = 0
        self.unknown_header = 0
        
    def match(self,server_ip,client_ip):
        if self.server_ip == server_ip and self.client_ip == client_ip:
            return 1
        return 0

SESSION_LIST = []
SESSION_FINAL = []


#for all row in csv
for i in range(0,rows):
    match = 0
    idx = -1
    #if SYN nad ACK are set then a new session
    if x[i,8] == 1 and x[i,9] == 1:
        for j in range(0,len(SESSION_LIST)):            #check if already these two ip are in a session
            match = SESSION_LIST[j].match(x[i,2],x[i,3]) 
            if match == 1:
                idx = j
                break
        
        if match == 1:                                   #session exists so increase the session count by 1
            SESSION_LIST[idx].session_count += 1
        else:                                           #if not then create a new session and append to list
            SESSION_LIST.append(Session_Master(x[i,2],x[i,3],x[i,0])) 
            
              
    #-----------------------------------------------------------------------------------------------------
             
    #if FIN nad ACK are set and dst port is 80 then find the session, list it and then remove
    elif x[i,12] == 1 and x[i,9] == 1 and x[i,7] == 80:
        match = 0
        idx = -1
        for j in range(0,len(SESSION_LIST)):            
            match = SESSION_LIST[j].match(x[i,3],x[i,2]) 
            if match == 1:                               #session exists so break
                idx = j
                break
            
        if match == 1:                                   #decrement the live session count and if it becomes 0
            SESSION_LIST[idx].session_count -= 1        #then remove it from the list
            if SESSION_LIST[idx].session_count == 0:
                finished_session = []
                pkt_count = SESSION_LIST[idx].packet_count
                total_resp = SESSION_LIST[idx].resp_success + SESSION_LIST[idx].resp_non_success
                req_count = SESSION_LIST[idx].request_count
                
                finished_session.append(SESSION_LIST[idx].server_ip)
                finished_session.append(SESSION_LIST[idx].client_ip)
                finished_session.append(SESSION_LIST[idx].start_frame_no)
                
                finished_session.append(SESSION_LIST[idx].df_count/pkt_count)
                finished_session.append(SESSION_LIST[idx].mf_count/pkt_count)
                finished_session.append(SESSION_LIST[idx].push_count/pkt_count)
                finished_session.append(SESSION_LIST[idx].urg_count/pkt_count)
                finished_session.append(SESSION_LIST[idx].total_len/pkt_count)                #avg length of packets in this session
                finished_session.append(SESSION_LIST[idx].request_count/pkt_count)            #request percentage
                finished_session.append(SESSION_LIST[idx].resp_success/total_resp)      #success response percentage
                finished_session.append(SESSION_LIST[idx].resp_non_success/total_resp)  #non success percentage
                if req_count != 0:
                    finished_session.append(SESSION_LIST[idx].unknown_header/req_count)     #unknown header percentage
                else:
                    finished_session.append(0)
                
                SESSION_FINAL.append(finished_session)   #append it to the final list
                SESSION_LIST.pop(idx)       #remove from ongoing list
            
    #------------------------------------------------------------------------------------------------------
    else:
        server_ip = ""
        dest_ip = ""
        
        if x[i,6] == 80:
            server_ip = x[i,2]
            dest_ip = x[i,3]
        else:
            server_ip = x[i,3]
            dest_ip = x[i,2]
            
        idx = -1
        stat = 0
        for j in range(0,len(SESSION_LIST)):
            stat = SESSION_LIST[j].match(server_ip,dest_ip)
            if stat == 1:
                idx = j
                break
            
        if idx != -1:
            SESSION_LIST[idx].packet_count += 1
            SESSION_LIST[idx].total_len += x[i,1]
            
            if x[i,4] == 1:
                SESSION_LIST[idx].df_count += 1
            if x[i,5] == 1:
                SESSION_LIST[idx].mf_count += 1
            if x[i,10] == 1:
                SESSION_LIST[idx].urg_count += 1
            if x[i,11] == 1:
                SESSION_LIST[idx].push_count += 1
            if x[i,13] is not np.nan:
                SESSION_LIST[idx].request_count += 1
            
            if x[i,14] is not np.nan:
                if x[i,14] == 200:
                    SESSION_LIST[idx].resp_success += 1
                else:
                    SESSION_LIST[idx].resp_non_success += 1
                    
            if x[i,15] is not np.nan and x[i,13] is np.nan:
                SESSION_LIST[idx].unknown_header += 1
                SESSION_LIST[idx].request_count += 1
        
#----------------------------------------Loop ends here------------------------------------------------------    
#-----------------------------Now add the remaining session tot the final list-------------------------------
           
for idx in range(0,len(SESSION_LIST)):
    finished_session = []
    pkt_count = SESSION_LIST[idx].packet_count
    total_resp = SESSION_LIST[idx].resp_success + SESSION_LIST[idx].resp_non_success
    req_count = SESSION_LIST[idx].request_count
    
    finished_session.append(SESSION_LIST[idx].server_ip)
    finished_session.append(SESSION_LIST[idx].client_ip)
    finished_session.append(SESSION_LIST[idx].start_frame_no)
    
    finished_session.append(SESSION_LIST[idx].df_count/pkt_count)
    finished_session.append(SESSION_LIST[idx].mf_count/pkt_count)
    finished_session.append(SESSION_LIST[idx].push_count/pkt_count)
    finished_session.append(SESSION_LIST[idx].urg_count/pkt_count)
    finished_session.append(SESSION_LIST[idx].total_len/pkt_count)                #avg length of packets in this session
    finished_session.append(SESSION_LIST[idx].request_count/pkt_count)            #request percentage
    finished_session.append(SESSION_LIST[idx].resp_success/total_resp)      #success response percentage
    finished_session.append(SESSION_LIST[idx].resp_non_success/total_resp)  #non success percentage
    if req_count != 0:
        finished_session.append(SESSION_LIST[idx].unknown_header/req_count)     #unknown header percentage
    else:
        finished_session.append(0)
    
    SESSION_FINAL.append(finished_session)                                  #append it to the final list
    
#---------------------------------------Data Mining ends here----------------------------------------------
    
x_sessions = pd.DataFrame(SESSION_FINAL)

x = []
x = x_sessions.iloc[:, :].values
import numpy
xdf = pd.DataFrame(x, columns=['0','1','2', '3', '4', '5', '6', '7', '8', '9', '10', '11'])
xdf.to_csv("x.csv")
x_sessions.to_csv("x_sessions.csv")

#This encoding is not needed here
'''
# Encoding the variables which are not just number
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
encoder_iv = LabelEncoder()

i = 1
while (i < 3):
    x[:, i] = encoder_iv.fit_transform(x[:, i])
    i = i + 1
    
x_encoded_view = pd.DataFrame(x)
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
'''

# Feature Scaling
from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
x[:,3:12] = sc.fit_transform(x[:,3:12])
x_scaled_view = pd.DataFrame(x)


# Applying PCA
from sklearn.decomposition import PCA
pca = PCA(n_components = None)
x_initial = x
x_initial[:,3:12] = pca.fit_transform(x[:,3:12])
x_initial_view = pd.DataFrame(x_initial)
explained_variance = pca.explained_variance_ratio_

#--------------------------------------------------------------------

#number of features as Principal components(Threshold = 90%data)
j=0
sum = 0
while(sum <= 0.97):
    sum = sum + explained_variance[j]
    j = j + 1
    
rows = len(x)

pca_1 = PCA(n_components = j)
x_final = np.zeros( (rows, j+1) )
x_final[:,0] = x[:,2]
x_final[:,1:j+1] = pca_1.fit_transform(x[:,3:12])
x_final_view = pd.DataFrame(x_final)

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Now starts the DBSCAN Portion
from mpl_toolkits.mplot3d import Axes3D
from sklearn.cluster import DBSCAN

#d2 = DBSCAN(eps = 0.3, min_samples = 15).fit(x_final)
#Labels2 = d2.labels_

class DBSCAN_Object:

    def __init__(self, PCA, i, j, k):
        self.principle_comps = PCA
        self.c1 = i
        self.c2 = j
        self.c3 = k

    def perform_DBSCAN(self, eps_val, min_nodes):
        dbscan = DBSCAN(eps = eps_val, min_samples = min_nodes).fit(self.principle_comps) 
        labels = dbscan.labels_ 
        
        labels = []
        color = []
        labels.extend(dbscan.labels_)
        
        for t in range(0, len(dbscan.labels_)):
            if dbscan.labels_[t] != -1:
                #dbscan.labels_[t] = 1
                color.append('b')
            else:
                #dbscan.labels_[t] = 5
                color.append('r')
        
        fig = plt.figure()
        ax = Axes3D(fig)
        plt.figure(figsize=(8, 6))
        plt.tight_layout()
        ax.scatter(self.principle_comps[:,0],self.principle_comps[:,1],self.principle_comps[:,2], c = color)
        ax.set_xlabel('Principal Component '+str(self.c1))
        ax.set_ylabel('Principal Component '+str(self.c2))
        ax.set_zlabel('Principal Component '+str(self.c3))
        pic_name = str(self.c1)+'_'+str(self.c2)+'_'+str(self.c3)+'.png'
        fig.savefig(pic_name,bbox_inches='tight',dpi=600)
        
        return labels
    
class Anomalous_Packet:
    
    def __init__(self,pckt_id,anm_count):
        self.pkt_id = pckt_id
        self.presence_as_anomalous = anm_count
    
    
DBSCAN_Objects = []
    
for m in range(1, j-1):
    for n in range(m+1, j):
        for o in range(n+1,j+1):
            pca_matrix = np.zeros((rows,3))
            pca_matrix[:,0] = x_final[:,m]
            pca_matrix[:,1] = x_final[:,n]
            pca_matrix[:,2] = x_final[:,o]
            DBSCAN_Objects.append(DBSCAN_Object(pca_matrix,m,n,o))

# Now we are finding out the anomaly count of each of the packets
Anomalous_count = np.zeros(rows)
for x in range(0,len(DBSCAN_Objects)):
    Labels = DBSCAN_Objects[x].perform_DBSCAN(0.32,15)
    for y in range(0,len(Labels)):
        if Labels[y] == -1:
            Anomalous_count[y] = Anomalous_count[y] + 1
            
            
# Separating those packets for which anomaly count is not equal zero
Anm_Packets = []
for x in range(0,len(Anomalous_count)):
    if Anomalous_count[x] > (len(DBSCAN_Objects)*0.90):
        a = Anomalous_Packet(x_final[x][0],Anomalous_count[x])
        Anm_Packets.append(a)

print(Anm_Packets) 
print(Anomalous_count) 
        

        
            
            

 
