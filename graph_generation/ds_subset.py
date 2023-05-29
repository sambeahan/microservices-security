import pandas as pd
import json
import matplotlib.pyplot as plt
import random

with open('ds_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

total = 0
sample_size = 240

sample = []

while total < sample_size:
    vuln = random.choice(list(vulns))
    code = vuln['code']

    sample.append({vuln['code']: vuln['repetitions']})
    total += vuln['repetitions']

    vulns.remove(vuln)

print(sample)