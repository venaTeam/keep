import os
import csv
from collections import defaultdict

services = [
    "actions", "cli", "conditions", "contextmanager", "event_subscriber",
    "exceptions", "functions", "identitymanager", "iohandler", "parser",
    "providers", "rulesengine", "searchengine", "secretmanager", "step",
    "throttles", "topologies", "validation", "workflowmanager"
]

stats = {s: {"api": 0, "event_handler": 0, "other": 0} for s in services}
file_stats = {s: {"api": [], "event_handler": [], "other": []} for s in services}

for root, dirs, files in os.walk("keep"):
    if "__pycache__" in root:
        continue
    
    # Identify who is doing the importing
    importer_comp = "other"
    if root.startswith("keep/api") or root == "keep/api":
        importer_comp = "api"
    elif root.startswith("keep/event_handler") or root == "keep/event_handler":
        importer_comp = "event_handler"
    else:
        # Check if it's one of the other services
        in_service = False
        for s in services:
            if root.startswith(f"keep/{s}"):
                in_service = True
                break
        if in_service:
            # We skip intra-service or cross-service for now to focus on API/EH usage
            # But we record it as 'other' to see if API/EH actually use it
            importer_comp = "other"

    for file in files:
        if not file.endswith(".py"):
            continue
        filepath = os.path.join(root, file)
        
        # Don't analyze the service's own files for imports of itself
        try:
            with open(filepath, "r") as f:
                content = f.read()
                for s in services:
                    # Skip if we are inside the service itself
                    if root.startswith(f"keep/{s}"):
                        continue
                        
                    patterns = [f"keep.{s}", f"from keep import {s}"]
                    for p in patterns:
                        if p in content:
                            stats[s][importer_comp] += 1
                            if len(file_stats[s][importer_comp]) < 5:
                                file_stats[s][importer_comp].append(filepath)
                            break
        except:
            pass

with open("service_usage.csv", "w") as f:
    writer = csv.writer(f)
    writer.writerow(["Service", "API_Count", "EH_Count", "Other_Count", "API_Files", "EH_Files", "Other_Files"])
    for s in services:
        writer.writerow([
            s,
            stats[s]["api"],
            stats[s]["event_handler"],
            stats[s]["other"],
            ";".join(file_stats[s]["api"]),
            ";".join(file_stats[s]["event_handler"]),
            ";".join(file_stats[s]["other"])
        ])
