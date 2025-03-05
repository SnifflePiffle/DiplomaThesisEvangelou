"""
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import Perceptron
from xgboost import XGBClassifier
import pickle

def match_classifier(cls):
    if isinstance(cls,RandomForestClassifier):
        return "RF"
    elif isinstance(cls,GradientBoostingClassifier):
        return "GBC"
    elif isinstance(cls,SVC):
        return "SVC"
    elif isinstance(cls,KNeighborsClassifier):
        return "KNC"
    elif isinstance(cls,XGBClassifier):
        return "XGB"
    elif isinstance(cls,Perceptron):
        return "PER"
    else:
        raise Exception("No valid classifier")

f = open('data_res_static.mar','rb')
stats = pickle.load(f)
y = {}
text = {}
for i,stat in enumerate(stats["params"]):
    text_label = ""
    for key in stat.keys():
        if key == "classifier":
            text_label += match_classifier(stat[key]) + "_"
        elif key == "classifier__class_weight":
            if stat[key]:
                text_label += str(stat[key][3]) + "_"
            else:
                text_label += "None" + "_"
        else:
            text_label += str(stat[key]) + "_"
    
    text_label = text_label.strip("_")
    if text_label.split("_")[0] in text:
        text[text_label.split("_")[0]].append('_'.join(text_label.split("_")[1:]))
    else:
        text[text_label.split("_")[0]] = ['_'.join(text_label.split("_")[1:])]

    if text_label.split("_")[0] in y:
        y[text_label.split("_")[0]].append(stats['mean_test_score'][i])
    else:
        y[text_label.split("_")[0]] = [stats['mean_test_score'][i]]

x = {}

for key in text.keys():
    x[key] = list(range(1,len(text[key])+1))

import matplotlib.pyplot as plt
from matplotlib import gridspec

from adjustText import adjust_text

fig = plt.figure(figsize=(8, 6))
gs = gridspec.GridSpec(2, 2, height_ratios=[5, 1])  # First row is twice the height of second row

# Larger subplot
ax1 = plt.subplot(gs[0, :])  # Spans both columns


# Smaller subplots
ax2 = plt.subplot(gs[1, :])

ax1.set_ylim(0.88, 1.05) # most of the data 
ax2.set_ylim(0.07,0.7)  # outliers only

# hide the spines between ax and ax2
ax1.spines.bottom.set_visible(False)
ax2.spines.top.set_visible(False)
ax1.xaxis.tick_top()
ax1.tick_params(labeltop=False)  # don't put tick labels at the top
ax2.xaxis.tick_bottom()


import random

# Now, let's turn towards the cut-out slanted lines.
# We create line objects in axes coordinates, in which (0,0), (0,1),
# (1,0), and (1,1) are the four corners of the Axes.
# The slanted lines themselves are markers at those locations, such that the
# lines keep their angle and position, independent of the Axes size or scale
# Finally, we need to disable clipping.

d = .5  # proportion of vertical to horizontal extent of the slanted line
kwargs = dict(marker=[(-1, -d), (1, d)], markersize=12,
              linestyle="none", color='k', mec='k', mew=1, clip_on=False)
ax1.plot([0, 1], [0, 0], transform=ax1.transAxes, **kwargs)
ax2.plot([0, 1], [1, 1], transform=ax2.transAxes, **kwargs)
for key in x.keys():
    if key == "PER":
        print(y[key])
    ax1.plot(x[key],y[key],marker='o',markersize=2,label=key)
    ax2.plot(x[key],y[key],marker='o',markersize=2,label=key)
    texts1 = []
    texts2 = []
    modular = random.randint(2,5)
    equal = random.randint(0,modular-1)
    for i,tex in enumerate(text[key]):
        offset = 0
        if i % modular == equal:
            ax1.text(x[key][i],y[key][i] + offset,text[key][i],fontsize=8,rotation=30,fontweight='semibold')
            if y[key][i] < 0.7:
                ax2.text(x[key][i],y[key][i]+ offset,text[key][i],fontsize=8,rotation=30,fontweight='semibold')

ax1.legend()

plt.xlabel("Combination number")
fig.ylabel("Macro Average F1-Score")
plt.title("Performance of different Estimator-Paremeter combinations")

plt.show()
"""

import matplotlib.pyplot as plt

res_arr = [
(0.42979942693409745,0.0,10,10,5),
(0.4292263610315186,0.0,10,20,5),
(0.38510028653295125,0.0,10,30,5),
(0.42836676217765046,0.0,20,10,5),
(0.44011461318051576,0.0,20,20,5),
(0.3756446991404011,0.0,20,30,5),
(0.4524355300859598,0.0,30,10,5),
(0.4378223495702006,0.0,30,20,5),
(0.3684813753581662,0.0,30,30,5),
(0.4300859598853869,0.0,10,10,10),
(0.42836676217765046,0.0,10,20,10),
(0.3813753581661891,0.0,10,30,10),
(0.43266475644699137,0.0,20,10,10),
(0.4312320916905444,0.0,20,20,10),
(0.37851002865329514,0.0,20,30,10),
(0.4269340974212034,0.0,30,10,10),
(0.4441260744985674,0.0,30,20,10),
(0.41948424068767903,0.0,30,30,10),
]
accuracy = [elem[0] for elem in res_arr]
mistakes = [elem[1] for elem in res_arr]
configurations = [f"{elem[2]}_{elem[3]}_{elem[4]}" for elem in res_arr]

plt.xlabel("Configuration (TLSH-Threshold_SSDEEP-Threshold_Classifiers-Per-Feature)")
plt.ylabel("Average Accuracy Score")
plt.title("Performance of different parameters / classifier number combinations")
plt.ylim(0,1)
plt.xticks(rotation=30)

plt.plot(configurations,accuracy,color='orange')
plt.show()

res_arr = [
(0.4584527220630373,0),
(0.49570200573065903,0),
(0.44126074498567336,0),
(0.4297994269340974,0),
(0.4498567335243553,0),
(0.47277936962750716,0),
(0.41260744985673353,0),
(0.41260744985673353,0),
(0.4269340974212034,0),
(0.4297994269340974,0),
]

accuracy = [elem[0] for elem in res_arr]

plt.plot(list(range(1,11)),accuracy,color='blue')


plt.xlabel("Iteration")
plt.ylabel("Score")
plt.title("Accuracy score over each iteration")
plt.ylim(0,1)

plt.show()
