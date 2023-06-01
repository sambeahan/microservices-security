import pandas as pd
import json
import matplotlib.pyplot as plt

with open('trivy_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

years = {}

for vuln in vulns:
    date = vuln["date"]
    if date != "":
        reps = vuln["repetitions"]
        year = date.split('/')[-1]
        year = int(year)
        if str(year) in years:
            years[str(year)] += reps
        else:
            years[str(year)] = reps

years = dict(sorted(years.items()))

keys = years.keys()
values = years.values()

fig, ax = plt.subplots()
fig.set_tight_layout(True)
fig.set_size_inches(5.2, 4)
plt.grid(color="#d4d7d9")
plt.xticks(rotation=90)
plt.bar(keys, values, color="#ff892e", zorder=3)

plt.xlabel("Year vulnerability added to NVD")
plt.ylabel("Vulnerability count")
plt.title("Years detected vulnerabilities were discovered (Trivy)")

plt.savefig("graphs/rq2_trivy.pdf")