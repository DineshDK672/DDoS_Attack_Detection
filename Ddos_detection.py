from sklearn.tree import DecisionTreeClassifier
from sklearn import model_selection
from sklearn.metrics import roc_curve
from matplotlib import pyplot as plt
from sklearn.metrics import roc_auc_score
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np
import warnings

def getData(fileName):
    Sample = pd.read_csv(fileName, nrows=500000)                 #Importing the dataset
    Sample.columns= [str(i).strip() for i in Sample.columns]            #Editing the column names
    print("\nSucessfully imported Dataset.......\n")

    SampleData=Sample[['Source IP','Source Port','Destination IP','Destination Port','Protocol','Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Fwd IAT Total','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Fwd Header Length','Bwd Header Length','Fwd Packets/s','Bwd Packets/s','Min Packet Length','Max Packet Length','Packet Length Mean', 'Average Packet Size','Avg Fwd Segment Size','Avg Bwd Segment Size']]                            #Choosing the columns for DDoS attack detection
    SampleData.fillna(0, inplace=True)
    SampleData.replace([np.inf, -np.inf], 0, inplace=True)
    label_encoder = LabelEncoder()
    for col in ['Source IP', 'Destination IP']:
        SampleData[col] = label_encoder.fit_transform(SampleData[col])      #To convert IP values from string to int

    print("Data pre-processing is completed...\n")
    print(SampleData.info())

    SampleTarget = Sample[['Label']]                                    #Choosing the target column
    SampleTarget.fillna("BENIGN", inplace=True)
    SampleTarget= np.reshape(SampleTarget,-1)   
    print("Target data pre-processing is completed...\n")                        #Editing the column shape into a 1D array

    return SampleData,SampleTarget
def treeEntropy(SampleData,SampleTarget):

    print("\nStarting the model for Decision Tree using entropy.....\n")
    parameters = [{"min_samples_leaf":[10,30,50,70,90]}]                #ML model for Decision Tree using entropy

    enTree = DecisionTreeClassifier(criterion="entropy",min_samples_leaf=5)
    tuned_enTree = model_selection.GridSearchCV(enTree,parameters,scoring="roc_auc",cv=10)
    tuned_enTree.fit(SampleData, SampleTarget)
    print("Best param for entropy is",list(tuned_enTree.best_params_.items())[0][1],"\n")

    yscores= model_selection.cross_val_predict(tuned_enTree,SampleData,SampleTarget,method="predict_proba",cv= 5)
    fpr,tpr,th=roc_curve(SampleTarget,yscores[:,1],pos_label="DrDoS_DNS")
    print("AUC Scores for entropy:",roc_auc_score(SampleTarget, yscores[:,1]),"\n")
    plt.xlabel("1 - Specificity")
    plt.ylabel("Sensitivity")
    plt.xlim(0,0.5)
    plt.ylim(0.5,1)
    plt.plot(fpr,tpr,'r', "Decision Tree - entropy" )
    plt.legend()
    plt.show()


def treeGini(SampleData,SampleTarget):

    print("\nStarting the model for Decision Tree using Gini index.....\n")

    parameters = [{"min_samples_leaf":[10,30,50,70,90]}]                #ML model for Decision Tree using Gini Index

    enTreeGini = DecisionTreeClassifier(criterion="gini", min_samples_leaf=5)
    tuned_enTreeGini = model_selection.GridSearchCV(enTreeGini,parameters,scoring="roc_auc",cv=10)
    tuned_enTreeGini.fit(SampleData, SampleTarget)
    print("Best param for gini is",list(tuned_enTreeGini.best_params_.items())[0][1],"\n")

    yscoresGini= model_selection.cross_val_predict(tuned_enTreeGini,SampleData,SampleTarget,method="predict_proba",cv=10)
    fpr,tpr,th=roc_curve(SampleTarget,yscoresGini[:,1],pos_label="DrDoS_DNS")
    print("AUC Scores for Gini:",roc_auc_score(SampleTarget, yscoresGini[:,1]),"\n")
    plt.xlabel("1 - Specificity")
    plt.ylabel("Sensitivity")
    plt.xlim(0,0.5)
    plt.ylim(0.5,1)
    plt.plot(fpr,tpr,'r', "Decision Tree - Gini" )
    plt.legend()
    plt.show()
    
def main():
    fileName  = input("Please enter the dataset name: ")
    warnings.filterwarnings("ignore")
    data,target = getData(fileName)
    treeEntropy(data,target)
    treeGini(data,target)

main()
