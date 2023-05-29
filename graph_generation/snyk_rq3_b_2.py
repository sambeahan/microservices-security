import json
import matplotlib.pyplot as plt
import numpy as np
import copy

with open("snyk_project_sevs.json", "r") as f:
    proj_vulns = json.load(f)

reps = []

proj_vulns = dict(sorted(proj_vulns.items(), key=lambda i: i[0].lower()))

for proj in proj_vulns:
    reps2 = [proj_vulns[proj]['critical'], proj_vulns[proj]['high'], proj_vulns[proj]['medium'], proj_vulns[proj]['low']]
    reps2.reverse()
    reps.append(reps2)

fig, ax = plt.subplots()
im = ax.imshow(reps)

project_titles = proj_vulns.keys()

plt.xticks(rotation=90)

ax.set_xticks(range(4))
ax.set_yticks(np.arange(len(project_titles)))

sevs=['Critical', 'High', 'Medium', 'Low']
sevs.reverse()

ax.set_xticklabels(sevs)
ax.set_yticklabels(project_titles)

for i in range(len(project_titles)):
    for j in range(4):
        text = ax.text(j, i, reps[i][j],
                       ha="center", va="center", color="w")

plt.xlabel("Vulnerability severity")
plt.ylabel("Project")
plt.title("Vulnerability Severity Frequency Within Each Project (Snyk)", loc="right")

fig.tight_layout()
fig.set_size_inches(9, 15)
plt.savefig('graphs/rq3_snyk_b.pdf')