import matplotlib.pyplot as plt
import glob
import os
filenames = glob.glob("EME2_*.txt")
filenames = sorted(filenames)
print(filenames)
for file in filenames:
    X,Y = [],[]
    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            value = [float(s) for s in line.split()]
            X.append(value[0])
            Y.append(value[1])
            print(value[0],value[1])
    file = os.path.splitext(file)[0]
    plt.plot(X,Y,label = file)
plt.legend()
plt.savefig('eme2.jpg')
plt.show()
