#!/usr/bin/python

import extractor as extr
import pandas as pd
import numpy as np

from sklearn import svm
from sklearn.naive_bayes import *
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split


class Predictor:

    __attr = extr.ATTR

    def __init__(self, inputFile):
        self.featureFile = inputFile
        self.__X = []
        self.__Y = []

        self.C = 1
        self.clf = None

    def load(self):
        data = pd.read_csv(self.featureFile, names = self.__attr, header=None)

        for row in data.itertuples(index=False, name=None):
            self.__X.append( list(row[1:]) )
            self.__Y.append( row[0] )

        self.__X = np.array(self.__X)
        self.__Y = np.array(self.__Y)

    def train(self):
        self.load()
        target_names = ['Normal', 'TCP SYN', 'ICMP' ]

        X_train, X_test, Y_train, Y_test = train_test_split(self.__X, self.__Y, test_size=0.4, random_state=0)



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
                        MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 3), random_state=1) ]


        for name, classifier in zip(names, classifiers):
            print name
            clf = classifier.fit(X_train, Y_train)
            print 'Accuracy - ' , clf.score(X_test, Y_test)
            Y_pred = classifier.predict(X_test)
            print(classification_report(Y_test, Y_pred, target_names=target_names))



if __name__ == '__main__':

    pred = Predictor('test.csv')
    pred.train()


