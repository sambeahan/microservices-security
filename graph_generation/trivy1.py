import json
import matplotlib.pyplot as plt

with open('trivy_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

reps = []
sevs = []

for vuln in vulns:
    reps.append(vuln["repetitions"])
    sevs.append(vuln["severity"])

x = sevs
y = reps

plt.scatter(x, y)

plt.xlabel("Severity of vulnerability")
plt.ylabel("Repetitions of vulnerability")

plt.show()