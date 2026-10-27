import argparse
from app.core import register,activate,active_version
p=argparse.ArgumentParser(description='Local trusted-model registry')
s=p.add_subparsers(dest='command',required=True)
r=s.add_parser('register');r.add_argument('source');r.add_argument('version')
a=s.add_parser('activate');a.add_argument('version')
s.add_parser('status')
args=p.parse_args()
if args.command=='register':register(args.source,args.version)
elif args.command=='activate':activate(args.version)
else:
    try:print(active_version())
    except FileNotFoundError:print('No active model')
