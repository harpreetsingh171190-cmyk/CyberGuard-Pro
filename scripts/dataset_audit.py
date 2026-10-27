import csv,json,hashlib
from pathlib import Path
p=Path('urls.csv')
with p.open(newline='',encoding='utf-8') as f:
    reader=csv.DictReader(f)
    if not {'url','label'}<=set(reader.fieldnames or []):raise ValueError('Required columns: url,label')
    count=sum(1 for _ in reader)
Path('reports').mkdir(exist_ok=True)
Path('reports/dataset_summary.json').write_text(json.dumps({'rows':count,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()},indent=2))
