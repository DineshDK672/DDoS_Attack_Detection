import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np

Sample = pd.read_csv("/Users/dineshdk/UWM/Cyber Security/Final Project/DrDoS_DNS.csv", nrows=500000)                 #Importing the dataset
Sample.columns= [str(i).strip() for i in Sample.columns]            #Editing the column names
print("\nSucessfully imported Dataset.......\n")

Sample=Sample[['Source IP','Source Port','Destination IP','Destination Port','Protocol','Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Fwd IAT Total','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Fwd Header Length','Bwd Header Length','Fwd Packets/s','Bwd Packets/s','Min Packet Length','Max Packet Length','Packet Length Mean', 'Average Packet Size','Avg Fwd Segment Size','Avg Bwd Segment Size', 'Label']]                            #Choosing the columns for DDoS attack detection
Sample.fillna(0, inplace=True)
Sample.replace([np.inf, -np.inf], 0, inplace=True)
label_encoder = LabelEncoder()
for col in ['Source IP', 'Destination IP']:
    Sample[col] = label_encoder.fit_transform(Sample[col])      #To convert IP values from string to int

print("Data pre-processing is completed...\n")
print(Sample.info())

Sample[['Label']].fillna("BENIGN", inplace=True)
# Sample[['Label']]= np.reshape(Sample[['Label']],-1)   
print("Target data pre-processing is completed...\n") 

Sample.to_csv("Pre-processed.csv")
