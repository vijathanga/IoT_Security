**IoT security using Machine Learning and SDN**

There are three modes in which the script can be run

1. CONTROLLER MODE
  * In this mode, the controller listens to incoming features from switch and predicts whether the traffic is malicious.
  * If malicious traffic pattern is found, the source of that traffic is blocked by installing appropriate flow table in switch using Floodlight SDn controller

2. SWITCH MODE
  * In this mode, the script extracts features from traffic flowing through switch and sends it to the controller.
  * Sampling interval for feature extraction can be set in constant.py file
    
3. TRAIN MODE
  * In train mode, features are extracted from all the pcaps mentioned in constant.py file and saved.
  * Using these features, various classifiers are trained and saved. 
