"""Local monitoring: aggregate recent audit actions, not raw URLs."""
import json
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from app.core import history
if __name__=='__main__':
    events=history(500)
    summary={'generated_utc':datetime.now(timezone.utc).isoformat(),'total_events':len(events),'by_action':dict(Counter(e['action'] for e in events))}
    Path('reports').mkdir(exist_ok=True)
    Path('reports/monitoring.json').write_text(json.dumps(summary,indent=2))
    print(json.dumps(summary,indent=2))
