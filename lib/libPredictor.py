#!/usr/bin/python

import os
import pandas as pd
import numpy as np
import constant as ct

from sklearn import svm
from sklearn.naive_bayes import *
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.externals import joblib


class Predictor:

    def __init__(self):
        self.__X = []
        self.__Y = []

        self.C = ct.REGULARISATION
        self.clf = None


    def load(self):
        data = pd.read_csv(ct.FEATURE_FILE, names = ct.FEATURES, header=None)

        for row in data.itertuples(index=False, name=None):
            self.__X.append( list(row[1:]) )
            self.__Y.append( row[0] )

        self.__X = np.array(self.__X)
        self.__Y = np.array(self.__Y)


    def train(self):
        self.load()

        X_train, X_test, Y_train, Y_test = train_test_split(self.__X, self.__Y, test_size=ct.TEST_SIZE, random_state=21)

        names = [ "Linear SVM",
                  "RBF SVM",
                  "Sigmoid SVM", 
                  "Gaussian Naive Bayes",
                  "Multinomial Naive Bayes",
                  "Bernoulli Naive Bayes",
                  "MLP Classifier" ]

        classifiers = [ svm.SVC(kernel='linear', C=self.C),
                        svm.SVC(kernel='rbf', gamma=0.7, C=self.C),
                        svm.SVC(kernel='sigmoid', gamma=0.2, C=self.C),
                        GaussianNB(),
                        MultinomialNB(),
                        BernoulliNB(),
                        MLPClassifier(solver='lbfgs', alpha=1e-2, hidden_layer_sizes=(10, 5), random_state=1) ]


        for clFile, name, classifier in zip(ct.CLASSIFIER_FILE, names, classifiers):
            print (name)
            clf = classifier.fit(X_train, Y_train)

            print ('Accuracy - ' , clf.score(X_test, Y_test))
            Y_pred = classifier.predict(X_test)

            print (classification_report(Y_test, Y_pred, target_names=ct.LABELS))

            filePath = os.path.join(ct.CLASSIFIER_PATH, clFile)
            joblib.dump(clf, filePath)
            