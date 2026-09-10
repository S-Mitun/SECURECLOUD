from sklearn.neural_network import MLPClassifier # Multi Layer Perceptron Classifier
#which is used for classification
x=[[0,0],[0,1],[1,0],[1,1]]
y=[0,1,1,0]
model=MLPClassifier(hidden_layer_sizes=(4,),max_iter=2000,random_state=1) # I-2,H-4,O-1
model.fit(x,y) #trains the model
#weights are calculated , random weights get assigned
#training continues for 2000 times
print(model.predict(x))