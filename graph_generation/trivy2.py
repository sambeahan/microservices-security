import pandas as pd
import json
import matplotlib.pyplot as plt

with open('trivy_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

reps = []
dates = []

for vuln in vulns:
    if vuln["date"] != "":
        reps.append(vuln["repetitions"])
        dates.append(vuln["date"])

dates = [pd.to_datetime(d) for d in dates]

x = dates
y = reps

plt.scatter(x, y)

plt.xlabel("Date vulnerability added to NVD")
plt.ylabel("Repetitions of vulnerability")

plt.show()