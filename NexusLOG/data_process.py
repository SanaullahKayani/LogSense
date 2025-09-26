import sys
sys.path.append('../')

import os
import re
import json
import pandas as pd
from collections import defaultdict
from tqdm import tqdm
import numpy as np
from logparser import Spell, Drain
from logparser import NexusDrain

# get [log key, delta time] as input for deeplog
input_dir  = os.path.expanduser('~/.dataset/nexus/')
output_dir = '../output/nexus/'  # The output directory of parsing results
log_file   = "NEXUS.log"  # The input log file name

log_structured_file = output_dir + log_file + "_structured.csv"
log_templates_file = output_dir + log_file + "_templates.csv"
log_sequence_file = output_dir + "nexus_sequence.csv"

def mapping():
    log_temp = pd.read_csv(log_templates_file)
    log_temp.sort_values(by = ["Occurrences"], ascending=False, inplace=True)
    log_temp_dict = {event: idx+1 for idx , event in enumerate(list(log_temp["EventId"])) }
    print(log_temp_dict)
    with open (output_dir + "nexus_log_templates.json", "w") as f:
        json.dump(log_temp_dict, f)


def parser(input_dir, output_dir, log_file, log_format, type='drain'):
    if type == 'spell':
        tau        = 0.5  # Message type threshold (default: 0.5)
        regex      = [
            "(/[-\w]+)+", #replace file path with *
            "(?<=blk_)[-\d]+" #replace block_id with *

        ]  # Regular expression list for optional preprocessing (default: [])

        parser = Spell.LogParser(indir=input_dir, outdir=output_dir, log_format=log_format, tau=tau, rex=regex, keep_para=False)
        parser.parse(log_file)

    elif type == 'drain':
        regex = [
            r"(?<=blk_)[-\d]+", # block_id
            r'\d+\.\d+\.\d+\.\d+',  # IP
            r"(/[-\w]+)+",  # file path
            #r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$',  # Numbers
        ]
        # the hyper parameter is set according to http://jmzhu.logpai.com/pub/pjhe_icws2017.pdf
        st = 0.5  # Similarity threshold
        depth = 5  # Depth of all leaf nodes


        parser = Drain.LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex, keep_para=False)
        parser.parse(log_file)

    elif type == 'nexusdrain':
        # Use CSV-aware NexusDrain to parse Nexus aggregated CSV logs
        # Optional regexes to mask sensitive tokens within Content when extracting parameters
        regex = [
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",  # UUID
            r"https?://[^\s\"]+",  # URL
            r"\d+\.\d+\.\d+\.\d+",  # IP
        ]
        parser = NexusDrain.LogParser(log_format, indir=input_dir, outdir=output_dir, rex=regex, keep_para=False)
        parser.parse(log_file)


def nexus_sampling(log_file, window_size=20, step=1):
    print("Loading", log_file)
    df = pd.read_csv(log_file, engine='c', na_filter=False, memory_map=True)

    # Map string EventId to integer ids as expected downstream
    with open(output_dir + "nexus_log_templates.json", "r") as f:
        event_num = json.load(f)
    df["EventId"] = df["EventId"].apply(lambda x: event_num.get(x, -1))

    # Build sliding window sequences over the entire log stream
    events = df["EventId"].astype(int).tolist()
    sequences = []
    for i in range(0, max(0, len(events) - window_size + 1), step):
        win = events[i:i + window_size]
        if len(win) == window_size and all(e > 0 for e in win):
            sequences.append(win)

    data_df = pd.DataFrame({
        'EventSequence': [str(seq) for seq in sequences]
    })
    data_df.to_csv(log_sequence_file, index=None)
    print("nexus sliding-window sampling done: {} sequences".format(len(sequences)))


def generate_train_test(hdfs_sequence_file, n=None, ratio=0.3):
    blk_label_dict = {}
    blk_label_file = os.path.join(input_dir, "anomaly_label.csv")
    blk_df = pd.read_csv(blk_label_file)
    for _ , row in tqdm(blk_df.iterrows()):
        blk_label_dict[row["BlockId"]] = 1 if row["Label"] == "Anomaly" else 0

    seq = pd.read_csv(hdfs_sequence_file)
    seq["Label"] = seq["BlockId"].apply(lambda x: blk_label_dict.get(x)) #add label to the sequence of each blockid

    normal_seq = seq[seq["Label"] == 0]["EventSequence"]
    normal_seq = normal_seq.sample(frac=1, random_state=20) # shuffle normal data

    abnormal_seq = seq[seq["Label"] == 1]["EventSequence"]
    normal_len, abnormal_len = len(normal_seq), len(abnormal_seq)
    train_len = n if n else int(normal_len * ratio)
    print("normal size {0}, abnormal size {1}, training size {2}".format(normal_len, abnormal_len, train_len))

    train = normal_seq.iloc[:train_len]
    test_normal = normal_seq.iloc[train_len:]
    test_abnormal = abnormal_seq

    df_to_file(train, output_dir + "train")
    df_to_file(test_normal, output_dir + "test_normal")
    df_to_file(test_abnormal, output_dir + "test_abnormal")
    print("generate train test data done")


def df_to_file(df, file_name):
    with open(file_name, 'w') as f:
        for _, row in df.items():
            f.write(' '.join([str(ele) for ele in eval(row)]))
            f.write('\n')


if __name__ == "__main__":
    # 1. parse NEXUS log
    log_format = '<Timestamp>,<LogLevel>,<LogPurpose>,<Hostname>,<Application>,<Service>,<Instance>,<Office>,<Country>,<Roles>,<Message>,<SourceFile>,<FileType>,<LogInfo>'  # Nexus log format
    parser(input_dir, output_dir, log_file, log_format, 'nexusdrain')
    mapping()
    nexus_sampling(log_structured_file, window_size=20, step=1)
    # 4. train/test split
    blk_label_file = os.path.join(input_dir, "anomaly_label.csv")
    if os.path.exists(blk_label_file):
        generate_train_test(log_sequence_file, n=4855)
    else:
        # Unsupervised fallback: shuffle and split sequences; no abnormal set
        print("anomaly_label.csv not found; performing unsupervised split")
        seq = pd.read_csv(log_sequence_file)
        # Randomize order deterministically
        seq = seq.sample(frac=1, random_state=20)
        total = len(seq)
        train_len = int(total * 0.7)
        train = seq.iloc[:train_len]["EventSequence"]
        test_normal = seq.iloc[train_len:]["EventSequence"]
        df_to_file(train, output_dir + "train")
        df_to_file(test_normal, output_dir + "test_normal")
        print("generate unsupervised train/test data done")
