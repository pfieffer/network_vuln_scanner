import json
from datetime import datetime

def generate_report(data: dict, filename: str):
    report = {
        "timestamp": str(datetime.utcnow()),
        "results": data
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)