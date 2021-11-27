import os, glob
from time import sleep
import pandas as pd

path = "./Work/Network_Security/kafka/Network-Traffic-Kafka-Spark-main/csv"

while(True):
        
        all_files = glob.glob(os.path.join(path, "part-*.csv"))
        df_from_each_file = (pd.read_csv(f, sep=',') for f in all_files)
        df_merged   = pd.concat(df_from_each_file, ignore_index=True)
        if os.path.isfile("./Work/Network_Security/kafka/Network-Traffic-Kafka-Spark-main/csv/merged.csv"):
                df_merged.to_csv( "./Work/Network_Security/kafka/Network-Traffic-Kafka-Spark-main/csv/merged.csv", mode='a', index=False, header=False)
        else:
                df_merged.to_csv( "./Work/Network_Security/kafka/Network-Traffic-Kafka-Spark-main/csv/merged.csv", mode='a', index=False, header=True)
        for filePath in all_files:
                try:
                        os.remove(filePath)
                except:
                        print("Error while deleting file : ", filePath)
        sleep(90)


