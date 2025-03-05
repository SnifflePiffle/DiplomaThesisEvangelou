import json
import os
import pandas as pd
import tlsh
import pyssdeep
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import Perceptron
from xgboost import XGBClassifier

import matplotlib.pyplot as plt

### TO-DO:

# Assume that packer is executed with default settings (add also to limitations)

# Static Analysis

# 1st: retrieve all section hashes from  to find out if consistent section for each packer (drop null)
# 2nd: organize findings (e.g. is ImpHash the same for one packer, Are API calls the same number between packed files?) in order to find out if packer is distinguishable

# See if I can add packers or samples

# Write that the already developed mechanisms (yara, DIE) will tell me statically which packer was used. What i add, is dynamic analysis for classification via hooking. For unknown packers, one could use the tool developed to match with my results.
# Write about the section names


## For dynamic mechanisms i create an array with the "signature of the packer", i.e. how many times each hooked function is called
## For static mechanisms I selected the features "Entropy","NumberOfSections","Sections","Relative EP Address","ImpHash"
## I also somewhat developed a mechanism for SSDEEP and TLSH comparisons, but will need help.

## K-fold (k=5 or k=10), cross validation, try 3-4 models
## Find out if same hash per packer TLSH, SSDEEP
## What features are the strongest? SHAP Framework = explainable AI (only if publication)
## Let's see if we can add something via the static features to dynamic ones

# For PostGraduate (i could probably say that the paper might be sent to a conference)

TOTAL_CLASSIFIERS = 5
k = 10
packers =['enigma', 'hyperion', 'nimcrypt2', 'nopacker', 'packer64', 'themida', 'upx', 'vmprotect']


def parse_json(data):
    result = {}
    for _, functions in data.items():
        for function_name, stats in functions.items():
            if function_name not in result:
                result[function_name] = int(stats["Times_Called"])
                if function_name == "LoadLibraryA":
                    result[function_name + "_libraries"] = len(stats["Libraries"])
                if function_name == "GetProcAddress":
                    result[function_name + "_functions"] = sum([len(value) for value in stats["Modules_Functions"].values()])
    return result


def dynamic_json():

    data = []
    columns = None
    for root,_,files in os.walk('results'):

        json_arr = {}
        file_name = ""
        for file in files:
            if not(file.endswith(".json")):
                continue
            try:
                json_file = open(root+"/"+file,'r')

                json_arr = parse_json(json.load(json_file))
            except:
                continue
                #print(file)
            if json_arr:

                col_names = list(json_arr.keys())
                col_names.sort()
                if not(columns):
                    columns = col_names
                enc_data = []
                for col in col_names:
                    enc_data.append(json_arr[col])
                file_name = file
                data.append((file_name.split("_")[0],file_name.rstrip(".json").split("-")[-1].split("_")[0],*enc_data))
           
    dynamic_df = pd.DataFrame(data=data,columns=["FileName","Packer",*columns])
    print(dynamic_df.head())
    print(dynamic_df["Packer"].unique())
    print(dynamic_df["LoadLibraryA_libraries"])
    #print(dynamic_df.where(dynamic_df["Packer"] == 'nopacker').dropna())
    return dynamic_df


def static_json():
    tlsh = []
    ssdeep = []
    features = []
    for root,_,files in os.walk('static_results'):

        file_count = 0
        json_arr = {}
        for file in files:
            if not(file.endswith(".json")):
                continue
            file_count += 1
            
            json_file = open(root+"/"+file,'r')
            json_arr = json.load(json_file)

            features.append((file.split("-")[0],file.split("-")[1].split("_")[0],json_arr["Entropy"],len(json_arr["Sections"]),','.join(arr[0] for arr in json_arr["Sections"]).split(","),int(json_arr["Image Base"],16),int(json_arr["Address EP"],16) - int(json_arr["Image Base"],16), json_arr["ImpHash"]))
            tlsh.append((file.split("-")[0],file.split("-")[1].split("_")[0],json_arr["TLSH"],[tlsh[1] for tlsh in json_arr["Per Section TLSH"]]))
            ssdeep.append((file.split("-")[0],file.split("-")[1].split("_")[0],json_arr["SSDEEP"],[ssdeep[1] for ssdeep in json_arr["Per Section SSDEEP"]]))

    tlsh_df=pd.DataFrame(tlsh,columns=["FileName","Packer","Overall TLSH","PerSectionTLSH"])
    ssdeep_df=pd.DataFrame(ssdeep,columns=["FileName","Packer","Overall SSDEEP","PerSectionSSDEEP"])
    features_df =pd.DataFrame(features,columns=["FileName","Packer","Entropy","NumberOfSections","Sections","Image Base","Relative EP Address","ImpHash"])
    print(features_df["Sections"])

    return tlsh_df,ssdeep_df,features_df

def custom_recall(class_name,pred,actual):
    assert len(pred) == len(actual)

    
    correct_true_pred = correct_true_act = 0

    for i in range(len(pred)):
        if actual[i] == class_name:
            correct_true_act += 1
            if pred[i] == class_name:
                correct_true_pred += 1
    
    if correct_true_pred == 0:
        return 0
    else:
        return correct_true_pred / correct_true_act
    
def custom_accuracy(actual,pred):
    assert len(pred) == len(actual)

    
    correct = 0
    mistakes = 0
    for i in range(len(pred)):
        if actual[i] == pred[i]:
            correct += 1
        elif pred[i] != "Not Found":
            mistakes += 1
    return (correct / len(pred),mistakes)

def custom_precision(class_name,pred,actual):
    assert len(pred) == len(actual)

    correct_true_pred = false_true_pred = 0

    for i in range(len(pred)):
        if pred[i] == class_name:
            if actual[i] == class_name:
                correct_true_pred += 1
            else:
                false_true_pred += 1
    
    if correct_true_pred == 0:
        return 0
    else:
        return correct_true_pred / (correct_true_pred + false_true_pred)

def custom_onehot(series):
    unique_elements = []
    for _,item in series.iteritems():
        for sec in item:
            if sec not in unique_elements:
                unique_elements.append(sec)

    final = []
    for _,item in series.iteritems():
        enc_str = ""
        for sec in unique_elements:
            if sec in item:
                enc_str += str('1')
            else:
                enc_str += str('0')
        res_int32 = []
        for i in range(0,len(enc_str),32):
            res_int32.append(int(enc_str[i:i+32],2))
        final.append(sum(res_int32))
        
    return pd.Series(final)



def calc_tlsh_ssdeep_dist(element,centers,mode,tlsh_thres,ssdeep_thres):
    total_dists = []
    for center in centers:
        hash_sum = 0
        for hash_e in element:
            if hash_e in ["TNULL","3::"]:
                continue
            hash_min = 1000
            hash_max = 0
            for hash_c in center:
                if hash_c in ["TNULL","3::"]:
                    continue
                if mode == "TLSH":
                    hash_min = min(hash_min,tlsh.diff(hash_e,hash_c))
                elif mode == "SSDEEP":
                    hash_max = max(hash_max,pyssdeep.compare(hash_e,hash_c))
                elif mode == "IMPHASH":
                    same = (hash_e == hash_c)
            if mode == "TLSH":
                hash_sum += (hash_min < tlsh_thres)
            elif mode == "SSDEEP":
                hash_sum += (hash_max > ssdeep_thres)
            elif mode == "IMPHASH":
                hash_sum += same
        total_dists.append(hash_sum)

    return total_dists

def classify_packer_tlsh_ssdeep(sum_list,packers,mode):
    if mode == "IMPHASH":
        return packers[sum_list.index(1)] if sum(sum_list) == 1 else "Ambiguous" if sum(sum_list) > 1 else "Not Found"
    return packers[sum_list.index(max(sum_list))] if max(sum_list) >= 2 else "Not Found"
   
def sort_dict(x):
    return {k: v for k, v in sorted(x.items(), key=lambda item: item[1])}

def generate_params():
    class_weights =  [None,dict((packers.index(packer),1.0) if packer != "nopacker" else (packers.index(packer),2.0) for packer in packers),dict((packers.index(packer),1.0) if packer != "nopacker" else (packers.index(packer),5.0) for packer in packers)] # give precedence to nopacker

    param1 = {}
    param1["classifier__n_estimators"]= [10,50,100,1000]
    param1["classifier__max_depth"] = [5,10,15]
    param1["classifier__class_weight"] = class_weights
    param1["classifier"] = [RandomForestClassifier(random_state=42)]

    param2 = {}
    param2["classifier__n_neighbors"] = [2,5,10,15,30,50]
    param2["classifier__leaf_size"] = [20,30,50]
    param2["classifier"] = [KNeighborsClassifier()]

    param3 = {}
    param3["classifier__n_estimators"] = [10,50,100,1000]
    param3["classifier__max_depth"] = [5,10,15]
    param3["classifier__learning_rate"] = [0.01,0.1,1,10]
    param3["classifier"] = [XGBClassifier()]

    param4 = {}
    param4["classifier__C"] = [0.01,0.1,1,10]
    param4["classifier__kernel"] = ["linear","poly","rbf"]
    param4["classifier__class_weight"] = class_weights
    param4["classifier"] = [SVC(random_state=42)]

    param5 = {}
    param5["classifier__n_estimators"] = [10,50,100,1000]
    param5["classifier__max_depth"] = [5,10,15]
    param5["classifier"] = [GradientBoostingClassifier(random_state=42)]

    return [param1 ,param2,param3,param4,param5]

def generate_params_static():
    param1 = {}
    param1["classifier__n_estimators"]= [10,50,100,1000]
    param1["classifier__max_depth"] = [5,10,15]
    param1["classifier"] = [RandomForestClassifier(random_state=42)]

    param2 = {}
    param2["classifier__n_neighbors"] = [2,5,10,15,30,50]
    param2["classifier__leaf_size"] = [20,30,50]
    param2["classifier"] = [KNeighborsClassifier()]

    param3 = {}
    param3["classifier__n_estimators"] = [10,50,100,1000]
    param3["classifier__max_depth"] = [5,10,15]
    param3["classifier__learning_rate"] = [0.01,0.1,1,10]
    param3["classifier"] = [XGBClassifier()]

    param4 = {}
    param4["classifier__penalty"] = ['l1','l2']
    param4["classifier__alpha"] = [0.0001,0.001,0.01,0.1]
    param4["classifier__tol"] = [0.001,0.01]
    param4["classifier"] = [Perceptron(random_state=42)]

    param5 = {}
    param5["classifier__n_estimators"] = [10,50,100,1000]
    param5["classifier__max_depth"] = [5,10,15]
    param5["classifier"] = [GradientBoostingClassifier(random_state=42)]

    return [param1 ,param2,param3,param4,param5]

def create_plot(acc,f1_mac,k):
    x = list(range(1,k+1))
    plt.plot(x,acc,label="accuracy")
    plt.plot(x,f1_mac,label="f1_macro")
    plt.ylim(0.8,1.05)
    plt.legend()
    plt.show()

if __name__ == "__main__":

    dynamic_df = dynamic_json()
    
    #dyn_df_nopacker = dynamic_df.where(dynamic_df["Packer"] == 'nopacker').dropna()
    #dynamic_df = dynamic_df.drop(dynamic_df.where(dynamic_df["Packer"] == 'nopacker').dropna().index)
    static_df = static_json()

    ## Estimator and parameters selection
    params = generate_params()

    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import GridSearchCV

    pipeline = Pipeline(steps=[("classifier",RandomForestClassifier(random_state=42))])
 
    X, y = dynamic_df[dynamic_df.columns[2:]],dynamic_df["Packer"]
    print(len(X.columns))
    y = y.apply(lambda x: packers.index(x))
    print(y)

    """

    # Splitting arrays or matrices into random train and test subsets
    
    #X_train = pd.concat([X_train,dyn_df_nopacker[dyn_df_nopacker.columns[2:]].iloc[:10]])
    #X_test = pd.concat([X_train,dyn_df_nopacker[dyn_df_nopacker.columns[2:]].iloc[10:]])

    #y_train = pd.concat([y_train,dyn_df_nopacker["Packer"].iloc[:10]])
    #y_test = pd.concat([y_train,dyn_df_nopacker["Packer"].iloc[10:]])

    # Training the model on the training dataset
    # fit function is used to train the model using the training sets as parameters

    grid = GridSearchCV(pipeline,params,scoring='f1_macro',n_jobs=5, cv=k,verbose=10).fit(X,y)

    a = grid.cv_results_
    import pickle
    f = open('dump_res.mar','wb')
    pickle.dump(a,f)
    exit()
    print(grid.best_estimator_,grid.best_params_,grid.best_score_)
    """

    from sklearn.model_selection import train_test_split
    # i.e. 70 % training dataset and 30 % test datasets

    clf = GradientBoostingClassifier(max_depth=5, n_estimators=50, random_state=42)

    chunk_size = len(X) // k

    acc = []
    prec = dict((packer,[]) for packer in packers)
    rec = dict((packer,[]) for packer in packers)
    f1 = dict((packer,[]) for packer in packers)
    f1_mac = []

    

    for i in range(k):

        y_test = y[chunk_size*i:chunk_size*(i+1)]
        y_train = y.drop(y_test.index)
        X_test = X[chunk_size*i:chunk_size*(i+1)]
        X_train = X.drop(X_test.index)

        print(X_test)
        clf.fit(X_train, y_train)
        
        # performing predictions on the test dataset
        y_pred = clf.predict(X_test)
        y_pred = y_pred.tolist()
        y_test = y_test.tolist()
        # metrics are used to find accuracy or error
        from sklearn import metrics  
        print()
        # using metrics module for accuracy calculation
        accuracy = metrics.accuracy_score(y_test, y_pred)
        acc.append(accuracy)

        f1_temp = []
        for packer,packer_name in enumerate(packers):
            recall = custom_recall(packer,y_pred,y_test)
            precision = custom_precision(packer,y_pred,y_test)
            if precision+recall == 0:
                f1_score = 0
            else:
                f1_score = 2*precision*recall / (precision+recall)
            f1_temp.append(f1_score)
            rec[packer_name].append(recall)
            prec[packer_name].append(precision)
            f1[packer_name].append(f1_score)
        
        f1_macro = sum(f1_temp) / len(f1_temp)
        f1_mac.append(f1_macro)

    create_plot(acc,f1_mac,k)

    avg_acc = sum(acc)/len(acc)
    avg_f1_mac = sum(f1_mac)/len(f1_mac)
    avg_rec = dict((packer,sum(val)/len(val)) for packer,val in rec.items())
    avg_prec = dict((packer,sum(val)/len(val)) for packer,val in prec.items())
    avg_f1 = dict((packer,sum(val)/len(val)) for packer,val in f1.items())


    g = open("output_dynamic.json","w")
    output_stats = json.dump([sort_dict(avg_prec),sort_dict(avg_rec),sort_dict(avg_f1)],g)
    g.close()
    print("Average Accuracy: " + str(avg_acc))
    print("Average F1 Macro: " + str(avg_f1_mac))


    ##################### STATIC ANALYSIS #############################


    features_df = static_df[2]

    X, y = features_df[features_df.columns[2:]],features_df["Packer"]
    y = y.apply(lambda x: packers.index(x))

    from sklearn.preprocessing import LabelEncoder

    encoder = LabelEncoder()
    X["ImpHash"] = encoder.fit_transform(X["ImpHash"])
    print(X["ImpHash"].value_counts())
    X["Sections"] = custom_onehot(X["Sections"])
    print(X["Sections"].value_counts())

    #params = generate_params_static()
    
    #pipeline = Pipeline(steps=[("classifier",RandomForestClassifier(random_state=42))])

    #grid = GridSearchCV(pipeline,params,scoring='f1_macro',n_jobs=5, cv=k,verbose=10).fit(X,y)

    #import pickle
    #g = open("data_res_static.mar","wb")
    #pickle.dump(grid.cv_results_,g)

    #print(grid.best_estimator_,grid.best_params_,grid.best_score_)



    clf = RandomForestClassifier(n_estimators = 10,max_depth=10, random_state=42)

    # Training the model on the training dataset
    # fit function is used to train the model using the training sets as parameters
    
    chunk_size = len(X) // k

    acc = []
    prec = dict((packer,[]) for packer in packers)
    rec = dict((packer,[]) for packer in packers)
    f1 = dict((packer,[]) for packer in packers)
    f1_mac = []

    for i in range(k):

        y_test = y[chunk_size*i:chunk_size*(i+1)]
        y_train = y.drop(y_test.index)
        X_test = X[chunk_size*i:chunk_size*(i+1)]
        X_train = X.drop(X_test.index)

        clf.fit(X_train, y_train)

        # performing predictions on the test dataset
        y_pred = clf.predict(X_test)
        y_pred = y_pred.tolist()
        y_test = y_test.tolist()
        # metrics are used to find accuracy or error
        from sklearn import metrics  
        print()
        # using metrics module for accuracy calculation

        accuracy = metrics.accuracy_score(y_test, y_pred)
        acc.append(accuracy)

        f1_temp = []
        for packer,packer_name in enumerate(packers):
            recall = custom_recall(packer,y_pred,y_test)
            precision = custom_recall(packer,y_pred,y_test)
            if precision+recall == 0:
                f1_score = 0
            else:
                f1_score = 2*precision*recall / (precision+recall)
            f1_temp.append(f1_score)
            rec[packer_name].append(recall)
            prec[packer_name].append(precision)
            f1[packer_name].append(f1_score)
        
        f1_macro = sum(f1_temp) / len(f1_temp)
        f1_mac.append(f1_macro)

    create_plot(acc,f1_mac,k)

    avg_acc = sum(acc)/len(acc)
    avg_f1_mac = sum(f1_mac)/len(f1_mac)
    avg_rec = dict((packer,sum(val)/len(val)) for packer,val in rec.items())
    avg_prec = dict((packer,sum(val)/len(val)) for packer,val in prec.items())
    avg_f1 = dict((packer,sum(val)/len(val)) for packer,val in f1.items())

    g = open("output_static.json","w")
    output_stats = json.dump([sort_dict(avg_prec),sort_dict(avg_rec),sort_dict(avg_f1)],g)
    g.close()
    print("Average Accuracy: " + str(avg_acc))
    print("Average F1 Macro: " + str(avg_f1_mac))

    tlsh_df = static_df[0]
    ssdeep_df = static_df[1]


    X_tlsh, y_tlsh = tlsh_df[tlsh_df.columns[2:]],tlsh_df["Packer"]
    X_ssdeep, y_ssdeep = ssdeep_df[ssdeep_df.columns[2:]],ssdeep_df["Packer"]

    X_imphash, y_imphash = features_df["ImpHash"], features_df["Packer"]
    """

    for c in [5,10]:
            for t in [10,20,30]:
                for s in [10,20,30]:
                    c_a = []
                    c_m = []
                    for fold in range(5):

                        X_tlsh_test = X_tlsh[chunk_size*fold:chunk_size*(fold+1)]
                        X_tlsh_train = X_tlsh.drop(X_tlsh_test.index)
                        y_tlsh_test = y_tlsh[chunk_size*fold:chunk_size*(fold+1)]
                        y_tlsh_train = y_tlsh.drop(y_tlsh_test.index)
                        X_ssdeep_train, X_ssdeep_test, y_ssdeep_train, y_ssdeep_test = X_ssdeep.iloc[X_tlsh_train.index],X_ssdeep.iloc[X_tlsh_test.index],y_ssdeep.iloc[y_tlsh_train.index],y_ssdeep.iloc[y_tlsh_test.index]
                        X_imphash_train, X_imphash_test, y_imphash_train, y_imphash_test = X_imphash.iloc[X_tlsh_train.index],X_imphash.iloc[X_tlsh_test.index],y_imphash.iloc[y_tlsh_train.index],y_imphash.iloc[y_tlsh_test.index]


                        import numpy as np
            
                        class_total = np.empty(shape=(3*c,len(X_tlsh_test)),dtype='<U20')
                        for i in range(c):
                            centers_tlsh = []
                            centers_ssdeep = []
                            centers_imphash = []

                            for packer in packers:
                                sample_tlsh = X_tlsh_train.where(y_tlsh_train == packer).dropna().sample(n=1)
                                sample_ssdeep = X_ssdeep_train.where(y_ssdeep_train == packer).dropna().sample(n=1)
                                sample_imphash = X_imphash_train.where(y_imphash_train == packer).dropna().sample(n=1)

                                centers_tlsh.append((*sample_tlsh["Overall TLSH"].to_list(), *sample_tlsh["PerSectionTLSH"].to_list()[0]))
                                centers_ssdeep.append((*sample_ssdeep["Overall SSDEEP"].to_list(), *sample_ssdeep["PerSectionSSDEEP"].to_list()[0]))
                                centers_imphash.append(sample_imphash)

                            y_pred = []
                            for element in X_tlsh_test.iterrows():
                                tlsh_elem = (element[1][0],*element[1][1])
                                tlsh_sum_list = calc_tlsh_ssdeep_dist(tlsh_elem,centers_tlsh,"TLSH",t,s)
                                y_pred.append(classify_packer_tlsh_ssdeep(tlsh_sum_list,packers,"TLSH"))
                            
                            class_total[3*i] = np.array(y_pred)

                            y_pred = []
                            for element in X_ssdeep_test.iterrows():
                                ssdeep_elem = (element[1][0],*element[1][1])
                                ssdeep_sum_list = calc_tlsh_ssdeep_dist(ssdeep_elem,centers_ssdeep,"SSDEEP",t,s)
                                y_pred.append(classify_packer_tlsh_ssdeep(ssdeep_sum_list,packers,"SSDEEP"))

                            class_total[3*i+1] = np.array(y_pred)

                            y_pred = []
                            for element in X_imphash_test:
                                imphash_elem = [element]
                                imphash_sum_list = calc_tlsh_ssdeep_dist(imphash_elem,centers_imphash,"IMPHASH",t,s)
                                y_pred.append(classify_packer_tlsh_ssdeep(imphash_sum_list,packers,"IMPHASH"))

                            class_total[3*i+2] = np.array(y_pred)


                        most_frequent_per_column = []
                        for col in range(class_total.shape[1]):
                            unique_elements, counts = np.unique(class_total[:, col], return_counts=True)
                            most_frequent_per_column.append(unique_elements[np.argmax(counts)])

                        y_pred = most_frequent_per_column

                        res= custom_accuracy(y_tlsh_test.to_list(),y_pred)
                        c_a.append(res[0])
                        c_m.append(res[1])
                    print(f"{sum(c_a)/5},{sum(c_m)/5},{t},{s},{c}")
    """
    t = 30
    s = 10
    c = 5
    c_a = []
    c_m = []
    chunk_size = len(X_tlsh)//10
    for fold in range(10):

                        X_tlsh_test = X_tlsh[chunk_size*fold:chunk_size*(fold+1)]
                        X_tlsh_train = X_tlsh.drop(X_tlsh_test.index)
                        y_tlsh_test = y_tlsh[chunk_size*fold:chunk_size*(fold+1)]
                        y_tlsh_train = y_tlsh.drop(y_tlsh_test.index)
                        X_ssdeep_train, X_ssdeep_test, y_ssdeep_train, y_ssdeep_test = X_ssdeep.iloc[X_tlsh_train.index],X_ssdeep.iloc[X_tlsh_test.index],y_ssdeep.iloc[y_tlsh_train.index],y_ssdeep.iloc[y_tlsh_test.index]
                        X_imphash_train, X_imphash_test, y_imphash_train, y_imphash_test = X_imphash.iloc[X_tlsh_train.index],X_imphash.iloc[X_tlsh_test.index],y_imphash.iloc[y_tlsh_train.index],y_imphash.iloc[y_tlsh_test.index]


                        import numpy as np
            
                        class_total = np.empty(shape=(3*c,len(X_tlsh_test)),dtype='<U20')
                        for i in range(c):
                            centers_tlsh = []
                            centers_ssdeep = []
                            centers_imphash = []

                            for packer in packers:
                                sample_tlsh = X_tlsh_train.where(y_tlsh_train == packer).dropna().sample(n=1)
                                sample_ssdeep = X_ssdeep_train.where(y_ssdeep_train == packer).dropna().sample(n=1)
                                sample_imphash = X_imphash_train.where(y_imphash_train == packer).dropna().sample(n=1)

                                centers_tlsh.append((*sample_tlsh["Overall TLSH"].to_list(), *sample_tlsh["PerSectionTLSH"].to_list()[0]))
                                centers_ssdeep.append((*sample_ssdeep["Overall SSDEEP"].to_list(), *sample_ssdeep["PerSectionSSDEEP"].to_list()[0]))
                                centers_imphash.append(sample_imphash)

                            y_pred = []
                            for element in X_tlsh_test.iterrows():
                                tlsh_elem = (element[1][0],*element[1][1])
                                tlsh_sum_list = calc_tlsh_ssdeep_dist(tlsh_elem,centers_tlsh,"TLSH",t,s)
                                y_pred.append(classify_packer_tlsh_ssdeep(tlsh_sum_list,packers,"TLSH"))
                            
                            class_total[3*i] = np.array(y_pred)

                            y_pred = []
                            for element in X_ssdeep_test.iterrows():
                                ssdeep_elem = (element[1][0],*element[1][1])
                                ssdeep_sum_list = calc_tlsh_ssdeep_dist(ssdeep_elem,centers_ssdeep,"SSDEEP",t,s)
                                y_pred.append(classify_packer_tlsh_ssdeep(ssdeep_sum_list,packers,"SSDEEP"))

                            class_total[3*i+1] = np.array(y_pred)

                            y_pred = []
                            for element in X_imphash_test:
                                imphash_elem = [element]
                                imphash_sum_list = calc_tlsh_ssdeep_dist(imphash_elem,centers_imphash,"IMPHASH",t,s)
                                y_pred.append(classify_packer_tlsh_ssdeep(imphash_sum_list,packers,"IMPHASH"))

                            class_total[3*i+2] = np.array(y_pred)


                        most_frequent_per_column = []
                        for col in range(class_total.shape[1]):
                            unique_elements, counts = np.unique(class_total[:, col], return_counts=True)
                            most_frequent_per_column.append(unique_elements[np.argmax(counts)])

                        y_pred = most_frequent_per_column

                        res= custom_accuracy(y_tlsh_test.to_list(),y_pred)
                        c_a.append(res[0])
                        c_m.append(res[1])
                        print(f"{res[0]},{res[1]}")
    print(f"{sum(c_a)/10},{sum(c_m)/10},{t},{s},{c}")







