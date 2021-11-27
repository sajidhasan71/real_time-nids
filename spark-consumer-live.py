from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from IPython.display import display

kafka_topic_name = "my-topic"
kafka_bootstrap_servers = "localhost:9092"

spark = SparkSession \
        .builder \
        .appName("Structured Streaming Pkt") \
        .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

# Construct a streaming DataFrame that reads from topic
pkt_df = spark \
        .readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", kafka_bootstrap_servers) \
        .option("subscribe", kafka_topic_name) \
        .load()

pkt_df.printSchema()
pkt_df1 = pkt_df.selectExpr("CAST(value AS STRING)", "timestamp")
pkt_df1.printSchema()
#pkt_schema_string = "Count INT, src_mac STRING, dst_mac STRING" 
pkt_schema_string = "len STRING, src STRING, dst STRING, ip_df STRING, ip_mf STRING, sport STRING, dport STRING, syn_flag STRING, ack_flag STRING, urg_flag STRING, push_flag STRING, fin_flag STRING, reset_flag STRING, ttl STRING"

pkt_df2 = pkt_df1 \
        .select(from_csv(col("value"), pkt_schema_string) \
                .alias("pkt"), "timestamp")
pkt_df2.printSchema()
pkt_df3 = pkt_df2.select("pkt.*", "timestamp")

pkt_df3.printSchema()

def learn(batch_df, batch_id):
        print(batch_id)
        batch_df.to_csv("op.csv")


query = pkt_df3\
        .coalesce(1)\
        .writeStream\
        .format("csv")\
        .option("path", "csv")\
        .trigger(processingTime='15 seconds') \
        .option("checkpointLocation", "checkpoint3")\
        .outputMode("append") \
        .option("format", "append")\
        .option("header", "true")\
        .start()
query.awaitTermination()

'''
query = pkt_df3 \
        .writeStream \
        .trigger(processingTime='5 seconds') \
        .outputMode("append") \
        .foreachBatch(learn) \
        .start()

query.awaitTermination()

query = pkt_df3 \
        .writeStream \
        .trigger(processingTime='5 seconds') \
        .outputMode("update") \
        .format("console") \
        .start()

query.awaitTermination()
'''
