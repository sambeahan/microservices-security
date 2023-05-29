import json
import matplotlib.pyplot as plt
import numpy as np
import copy

with open("project_vulns.json", "r") as f:
    proj_vulns = json.load(f)

proj_vulns = dict(sorted(proj_vulns.items(), key=lambda i: i[0].lower()))

sevs = range(11)[::-1]
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

reps = np.array(reps)
reps = np.transpose(reps)
reps = np.flip(reps, axis=0)

rep_labels = np.array(rep_labels)
rep_labels = np.transpose(rep_labels)
rep_labels = np.flip(rep_labels, axis=0)

fig, ax = plt.subplots()
im = ax.imshow(reps)

project_titles = proj_vulns.keys()

plt.xticks(rotation=-90)

ax.set_xticks(np.arange(len(project_titles)))
ax.set_yticks(range(11))

ax.set_xticklabels(project_titles)
ax.set_yticklabels(sevs)

for i in range(11):
    for j in range(len(project_titles)):
        text = ax.text(j, i, rep_labels[i, j],
                       ha="center", va="center", color="w")
        
plt.xlabel("Project")
plt.ylabel("Vulnerability severity")
plt.title("Normalised Vulnerability Severity Frequency Within Each Project (Trivy)")

fig.tight_layout()
fig.set_size_inches(11, 7.2)
plt.savefig('graphs/rq3_trivy_c.png')