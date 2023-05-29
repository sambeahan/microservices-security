import json
import matplotlib.pyplot as plt
import numpy as np
import copy

with open("project_vulns.json", "r") as f:
    proj_vulns = json.load(f)

proj_vulns = dict(sorted(proj_vulns.items(), key=lambda i: i[0].lower()))

sevs = range(11)
reps = []



for proj in proj_vulns:
    reps2 = [0] * 11
    for vuln in proj_vulns[proj]:
        sev = vuln['sev']
        if sev != '':
            sev = float(sev)
            reps2[round(sev)] += vuln["reps"]
    print(reps2)
    reps.append(reps2)





for i in range(len(reps)):
    max = 1
    for j in range(len(reps[i])):
        print(reps[i][j])
        if reps[i][j] > max:
            max = reps[i][j]
            print("max is now", max)
    
    for j in range(len(reps[i])):
        reps[i][j] /= max


    

rep_labels = copy.deepcopy(reps)
for i in range(len(reps)):
    for j in range(len(reps[i])):
        rep_labels[i][j] = round(rep_labels[i][j], 1)

fig, ax = plt.subplots()
im = ax.imshow(reps)

project_titles = proj_vulns.keys()

ax.set_xticks(range(11))
ax.set_yticks(np.arange(len(project_titles)))

ax.set_xticklabels(sevs)
ax.set_yticklabels(project_titles)

for i in range(len(project_titles)):
    for j in range(11):
        text = ax.text(j, i, rep_labels[i][j],
                       ha="center", va="center", color="w")
        
plt.xlabel("Vulnerability severity")
plt.ylabel("Project")
plt.title("Normalised Vulnerability Severity Frequency Within Each Project (Trivy)", loc="right")

fig.tight_layout()
fig.set_size_inches(8, 10)
plt.savefig('graphs/rq3_trivy_c_2.pdf')