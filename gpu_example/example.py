import json
import sys
import numpy as np
import tensorflow as tf

# Read in data from file
data = np.genfromtxt(sys.argv[1], delimiter=',')
data = np.reshape(data,(2,2))

# Generate graph of gpu computations
graph = tf.Graph()
with graph.as_default():
    with tf.device('/gpu:0'):
        X = tf.placeholder("float64",[2,2])
        npmatrix = np.array([[10.0, 2.0], [-5.0, 8.78]])
        matrix = tf.Variable(npmatrix)
        y = tf.matmul(X, matrix)

    # Run the computations on the input
    with tf.Session() as sess:
        sess.run(tf.global_variables_initializer())
        output = sess.run(y, {X: data})

# print out results
print(json.dumps(output.flatten()))
