#!/usr/bin/python

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

from plotly.graph_objs import *
import plotly.plotly as py
import plotly.tools as tls


FEATURES = ["label", "prot", "syn", "fin", "rst", "psh", "ack", "urg", "ece", "cwr", "echoReq", "echoRply",
                     "meanArrTime", "varArrTime", "minArrTime", "maxArrTime", 
                     "meanPktLen",  "varPktLen",  "minBytes",   "maxBytes",   "totPkt", "totBytes"]

feat =  ["prot", "syn", "fin", "rst", "psh", "ack", "urg", "ece", "cwr", "echoReq", "echoRply",
                     "meanArrTime", "varArrTime", "minArrTime", "maxArrTime", 
                     "meanPktLen",  "varPktLen",  "minBytes",   "maxBytes",   "totPkt", "totBytes"]

FEATURE_FILE = "./res/features_1s.csv"



def svd(self):
    data = pd.read_csv(FEATURE_FILE, names = FEATURES, header=None)

    for row in data.itertuples(index=False, name=None):
        self.__X.append( list(row[1:]) )
        self.__Y.append( row[0] )

    self.__X = np.array(self.__X)
    self.__Y = np.array(self.__Y)

    X_std = StandardScaler().fit_transform(self.__X)
    
    cov_mat = np.cov(X_std.T)
    eig_vals, eig_vecs = np.linalg.eig(cov_mat)

    u,s,v = np.linalg.svd(X_std.T)

    print s
    print eig_vals

    # Make a list of (eigenvalue, eigenvector) tuples
    eig_pairs = [(np.abs(eig_vals[i]), eig_vecs[:,i]) for i in range(len(eig_vals))]


    tot = sum(eig_vals)
    var_exp = [(i / tot)*100 for i in eig_vals]
    cum_var_exp = np.cumsum(var_exp)

    for name, var in zip(feat, var_exp):
        print name,",", var



if __name__ == '__main__':
    P = Predictor()
    P.svd()
