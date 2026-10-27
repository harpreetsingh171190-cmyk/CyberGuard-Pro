"""CLI: python -m app.batch_cli input.csv output.csv"""
import argparse, csv, json
from pathlib import Path
from app.core import score_urls

def run(source, destination, chunk_size=100):
    if not 1 <= chunk_size <= 500: raise ValueError('Chunk size must be 1..500')
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve(): raise ValueError('Input and output must differ')
    if source.stat().st_size > 10_000_000: raise ValueError('CSV input exceeds 10 MB')
    count=0
    with source.open(newline='',encoding='utf-8-sig') as inp, destination.open('w',newline='',encoding='utf-8') as out:
        reader=csv.DictReader(inp)
        if not reader.fieldnames or 'url' not in reader.fieldnames: raise ValueError('Missing url column')
        writer=csv.DictWriter(out,fieldnames=['url','risk_score','risk_band']);writer.writeheader()
        chunk=[]
        for row in reader:
            chunk.append(row['url'])
            if len(chunk)==chunk_size:
                writer.writerows(score_urls(chunk));count+=len(chunk);chunk=[]
        if chunk:writer.writerows(score_urls(chunk));count+=len(chunk)
    return count

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='CyberGuard offline batch scanner')
    parser.add_argument('input');parser.add_argument('output');parser.add_argument('--chunk-size',type=int,default=100)
    args=parser.parse_args()
    print(json.dumps({'processed':run(args.input,args.output,args.chunk_size),'output':args.output}))
