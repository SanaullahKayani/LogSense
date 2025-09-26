"""
Description : Drain-style parser for Nexus CSV logs (same outputs as Drain)
Author      : Custom
License     : MIT
"""

import os
import re
import hashlib
import pandas as pd
from datetime import datetime


class Logcluster:
    def __init__(self, logTemplate='', logIDL=None):
        self.logTemplate = logTemplate
        if logIDL is None:
            logIDL = []
        self.logIDL = logIDL


class Node:
    def __init__(self, childD=None, depth=0, digitOrtoken=None):
        if childD is None:
            childD = dict()
        self.childD = childD
        self.depth = depth
        self.digitOrtoken = digitOrtoken


class LogParser:
    def __init__(self, log_format=None, indir='./', outdir='./result/', depth=4, st=0.4,
                 maxChild=100, rex=None, keep_para=True):
        self.path = indir
        self.savePath = outdir
        self.log_format = log_format
        self.keep_para = keep_para
        self.logName = None
        self.df_log = None
        self.rex = rex or []
        # Drain-style hyperparameters
        self.depth = depth - 2 if depth and depth >= 2 else 1
        self.st = st
        self.maxChild = maxChild

    def parse(self, logName):
        print('Parsing file (NexusDrain): ' + os.path.join(self.path, logName))
        start_time = datetime.now()
        self.logName = logName

        # Prepare Drain-style structures
        rootNode = Node()
        logCluL = []

        # Load CSV and build df_log with LineId and Content (original message)
        input_path = os.path.join(self.path, self.logName)
        df_src = pd.read_csv(input_path)

        # Choose message column priority: Message > ExampleMessage > CanonicalMessage
        msg_col = None
        for c in ['Message', 'ExampleMessage', 'CanonicalMessage']:
            if c in df_src.columns:
                msg_col = c
                break
        if msg_col is None:
            # Fallback: join a few textual columns
            candidates = [c for c in ['LogPurpose','LogLevel','Application','Service'] if c in df_src.columns]
            if candidates:
                msg_col = '__synthetic__'
                df_src[msg_col] = df_src[candidates].astype(str).agg(' '.join, axis=1)
            else:
                msg_col = None

        occ_col = None
        for c in ['Occurrences','Count','Frequency']:
            if c in df_src.columns:
                occ_col = c
                break

        # Build working df_log (LineId, Content)
        contents = []
        line_ids = []
        line_id = 1
        for _, row in df_src.iterrows():
            content = str(row.get(msg_col, '')) if msg_col else ''
            occurrences = int(row.get(occ_col, 1)) if occ_col else 1
            for _ in range(max(1, occurrences)):
                contents.append(content)
                line_ids.append(line_id)
                line_id += 1

        self.df_log = pd.DataFrame({'LineId': line_ids, 'Content': contents})

        # Run Drain-style clustering over the synthetic line stream
        count = 0
        for _, line in self.df_log.iterrows():
            logID = line['LineId']
            logmessageL = self.preprocess(line['Content']).strip().split()
            matchCluster = self.treeSearch(rootNode, logmessageL)

            if matchCluster is None:
                newCluster = Logcluster(logTemplate=logmessageL, logIDL=[logID])
                logCluL.append(newCluster)
                self.addSeqToPrefixTree(rootNode, newCluster)
            else:
                newTemplate = self.getTemplate(logmessageL, matchCluster.logTemplate)
                matchCluster.logIDL.append(logID)
                if ' '.join(newTemplate) != ' '.join(matchCluster.logTemplate):
                    matchCluster.logTemplate = newTemplate

            count += 1
            if count % 1000 == 0 or count == len(self.df_log):
                print('Processed {0:.1f}% of log lines.'.format(count * 100.0 / len(self.df_log)), end='\r')

        if not os.path.exists(self.savePath):
            os.makedirs(self.savePath)

        # Output exactly like Drain (handles writing structured and templates)
        self.outputResult(logCluL)
        print('Parsing done. [Time taken: {!s}]'.format(datetime.now() - start_time))

    def preprocess(self, line: str) -> str:
        # Default masking rules for Nexus messages if no rex provided
        local_rex = self.rex if self.rex else [
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",  # UUID
            r"\d+\.\d+\.\d+\.\d+",  # IPv4
            r"https?://[^\s\"]+",  # URL
            r"(?<=\D)[-+]?\d+(?:\.\d+)?|^[-+]?\d+(?:\.\d+)?$",  # Numbers
            r"<[^>]+>",  # angle-bracketed tokens
        ]
        for currentRex in local_rex:
            line = re.sub(currentRex, '<*>', line)
        return line

    # Drain-style helpers below
    def hasNumbers(self, s):
        return any(char.isdigit() for char in s)

    def treeSearch(self, rn, seq):
        retLogClust = None
        seqLen = len(seq)
        if seqLen not in rn.childD:
            return retLogClust
        parentn = rn.childD[seqLen]
        currentDepth = 1
        for token in seq:
            if currentDepth >= self.depth or currentDepth > seqLen:
                break
            if token in parentn.childD:
                parentn = parentn.childD[token]
            elif '<*>' in parentn.childD:
                parentn = parentn.childD['<*>']
            else:
                return retLogClust
            currentDepth += 1
        logClustL = parentn.childD
        retLogClust = self.fastMatch(logClustL, seq)
        return retLogClust

    def addSeqToPrefixTree(self, rn, logClust):
        seqLen = len(logClust.logTemplate)
        if seqLen not in rn.childD:
            firtLayerNode = Node(depth=1, digitOrtoken=seqLen)
            rn.childD[seqLen] = firtLayerNode
        else:
            firtLayerNode = rn.childD[seqLen]
        parentn = firtLayerNode
        currentDepth = 1
        for token in logClust.logTemplate:
            if currentDepth >= self.depth or currentDepth > seqLen:
                if len(parentn.childD) == 0:
                    parentn.childD = [logClust]
                else:
                    parentn.childD.append(logClust)
                break
            if token not in parentn.childD:
                if not self.hasNumbers(token):
                    if '<*>' in parentn.childD:
                        if len(parentn.childD) < self.maxChild:
                            newNode = Node(depth=currentDepth + 1, digitOrtoken=token)
                            parentn.childD[token] = newNode
                            parentn = newNode
                        else:
                            parentn = parentn.childD['<*>']
                    else:
                        if len(parentn.childD) + 1 < self.maxChild:
                            newNode = Node(depth=currentDepth + 1, digitOrtoken=token)
                            parentn.childD[token] = newNode
                            parentn = newNode
                        elif len(parentn.childD) + 1 == self.maxChild:
                            newNode = Node(depth=currentDepth + 1, digitOrtoken='<*>')
                            parentn.childD['<*>'] = newNode
                            parentn = newNode
                        else:
                            parentn = parentn.childD['<*>']
                else:
                    if '<*>' not in parentn.childD:
                        newNode = Node(depth=currentDepth + 1, digitOrtoken='<*>')
                        parentn.childD['<*>'] = newNode
                        parentn = newNode
                    else:
                        parentn = parentn.childD['<*>']
            else:
                parentn = parentn.childD[token]
            currentDepth += 1

    def seqDist(self, seq1, seq2):
        assert len(seq1) == len(seq2)
        simTokens = 0
        numOfPar = 0
        for token1, token2 in zip(seq1, seq2):
            if token1 == '<*>':
                numOfPar += 1
                continue
            if token1 == token2:
                simTokens += 1
        retVal = float(simTokens) / len(seq1)
        return retVal, numOfPar

    def fastMatch(self, logClustL, seq):
        retLogClust = None
        maxSim = -1
        maxNumOfPara = -1
        maxClust = None
        for logClust in logClustL:
            curSim, curNumOfPara = self.seqDist(logClust.logTemplate, seq)
            if curSim > maxSim or (curSim == maxSim and curNumOfPara > maxNumOfPara):
                maxSim = curSim
                maxNumOfPara = curNumOfPara
                maxClust = logClust
        if maxSim >= self.st:
            retLogClust = maxClust
        return retLogClust

    def getTemplate(self, seq1, seq2):
        assert len(seq1) == len(seq2)
        retVal = []
        i = 0
        for word in seq1:
            if word == seq2[i]:
                retVal.append(word)
            else:
                retVal.append('<*>')
            i += 1
        return retVal

    def outputResult(self, logClustL):
        log_templates = [0] * self.df_log.shape[0]
        log_templateids = [0] * self.df_log.shape[0]
        df_events = []
        for logClust in logClustL:
            template_str = ' '.join(logClust.logTemplate)
            occurrence = len(logClust.logIDL)
            template_id = hashlib.md5(template_str.encode('utf-8')).hexdigest()[0:8]
            for logID in logClust.logIDL:
                logID -= 1
                log_templates[logID] = template_str
                log_templateids[logID] = template_id
            df_events.append([template_id, template_str, occurrence])

        df_event = pd.DataFrame(df_events, columns=['EventId', 'EventTemplate', 'Occurrences'])
        self.df_log['EventId'] = log_templateids
        self.df_log['EventTemplate'] = log_templates

        if self.keep_para:
            self.df_log["ParameterList"] = self.df_log.apply(self.get_parameter_list, axis=1)
        self.df_log.to_csv(os.path.join(self.savePath, self.logName + '_structured.csv'), index=False)

        occ_dict = dict(self.df_log['EventTemplate'].value_counts())
        df_event = pd.DataFrame()
        df_event['EventTemplate'] = self.df_log['EventTemplate'].unique()
        df_event['EventId'] = df_event['EventTemplate'].map(lambda x: hashlib.md5(str(x).encode('utf-8')).hexdigest()[0:8])
        df_event['Occurrences'] = df_event['EventTemplate'].map(occ_dict)
        df_event.to_csv(os.path.join(self.savePath, self.logName + '_templates.csv'), index=False,
                        columns=["EventId", "EventTemplate", "Occurrences"])

    def _mask_dynamic_tokens(self, message: str) -> str:
        """Create a simple template from a concrete message by masking dynamic tokens.
        This is a fallback when CanonicalMessage is not available.
        """
        s = message
        # UUID
        s = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b", '<UUID>', s)
        # Email
        s = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", '<EMAIL>', s)
        # URL
        s = re.sub(r"https?://[^\s\"]+", '<URL>', s)
        # Numbers
        s = re.sub(r"(?<=\D)[-+]?\d+(?:\.\d+)?|^[-+]?\d+(?:\.\d+)?$", '<NUM>', s)
        return s

    def get_parameter_list(self, row):
        template_regex = re.sub(r"<.{1,5}>", "<*>", str(row["EventTemplate"]))
        if "<*>" not in template_regex:
            return []
        template_regex = re.sub(r'([^A-Za-z0-9])', r'\\\\1', template_regex)
        template_regex = re.sub(r' +', r'\\s+', template_regex)
        template_regex = "^" + template_regex.replace("\\<\\*\\>", "(.*?)") + "$"
        parameter_list = re.findall(template_regex, row["Content"])
        parameter_list = parameter_list[0] if parameter_list else ()
        parameter_list = list(parameter_list) if isinstance(parameter_list, tuple) else [parameter_list]
        return parameter_list


