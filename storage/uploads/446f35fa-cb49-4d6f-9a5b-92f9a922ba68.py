import tensorflow as tf
from tensorflow.keras import dataset
(x_train,y_train),(x_test,y_test)
x_train=x_train/255.0 #0-255
x_test=x_test/255.0
model=models.Sequential([layers.Conv2d(32,(3,3),activation='relu',input_shape=(32,32,3)),layers.maxPooling2D((2,2)),layers.flatten(),layers.dense(64,activation='relu'),layers.dense(10,activation='softmax')])
model.compile(optimizer='adam',loss='sparse_categorical_crossentropy',metrics=['accuracy'])
model.fit(x_train,y_train,epochs=5)
# x=training images, y=training labels
# first convulational model
# first pooling layer
loss,accuracy=model.evaluate(x_test,y_test)
print(accuracy)