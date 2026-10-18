#!/usr/bin/env python3
"""Explicitly provision a Redis cluster epoch. Runtime never recreates lost state."""
import argparse, os, secrets, socket, tempfile
from pathlib import Path

SCRIPT = '''local old=redis.call('GET',KEYS[1])
if ARGV[1]=='init' and old then
 if not redis.call('GET',KEYS[2]) then return redis.error_reply('missing clock: fence nodes and rotate epoch') end
 return old
end
if ARGV[1]=='rotate' and old~=ARGV[2] then return redis.error_reply('epoch changed or missing; refusing rotation') end
local now=redis.call('TIME')[1]
redis.call('SET',KEYS[2],now)
redis.call('SET',KEYS[1],ARGV[3])
return ARGV[3]'''

def command(sock, *args):
    parts=[arg if isinstance(arg,bytes) else str(arg).encode() for arg in args]
    sock.sendall(b'*'+str(len(parts)).encode()+b'\r\n'+b''.join(b'$'+str(len(p)).encode()+b'\r\n'+p+b'\r\n' for p in parts))
    stream=sock.makefile('rb')
    def read():
        line=stream.readline(4096)
        if not line.endswith(b'\r\n'): raise RuntimeError('invalid Redis reply')
        kind,value=line[:1],line[1:-2]
        if kind==b'-': raise RuntimeError(value.decode(errors='replace'))
        if kind in (b'+',b':'): return value.decode()
        if kind==b'$':
            size=int(value)
            if size==-1:return None
            if not 0<=size<=4096:raise RuntimeError('oversized Redis reply')
            data=stream.read(size+2)
            if len(data)!=size+2 or data[-2:]!=b'\r\n':raise RuntimeError('truncated Redis reply')
            return data[:-2].decode()
        if kind==b'*':return [read() for _ in range(int(value))]
        raise RuntimeError('unsupported Redis reply')
    try:return read()
    finally:stream.close()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--address',default='127.0.0.1:6379')
    p.add_argument('--namespace',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--password-file',type=Path)
    p.add_argument('--username',default='')
    p.add_argument('--rotate',metavar='EXPECTED_64_HEX_EPOCH',help='requires all proxies fenced before rotation')
    args=p.parse_args()
    if not 1<=len(args.namespace)<=64 or not all(c.isascii() and (c.isalnum() or c in '_-') for c in args.namespace):p.error('invalid namespace')
    if args.rotate and (len(args.rotate)!=64 or any(c not in '0123456789abcdef' for c in args.rotate)):p.error('invalid expected epoch')
    host,port=args.address.rsplit(':',1)
    with socket.create_connection((host.strip('[]'),int(port)),timeout=3) as sock:
        if args.password_file:
            password=args.password_file.read_bytes().removesuffix(b'\n')
            command(sock,'AUTH',*([args.username] if args.username else []),password)
        policy=command(sock,'CONFIG','GET','maxmemory-policy')
        memory=command(sock,'CONFIG','GET','maxmemory')
        if policy!=['maxmemory-policy','noeviction'] or len(memory)!=2 or int(memory[1])<=0:
            raise RuntimeError('a dedicated Redis primary with maxmemory > 0 and maxmemory-policy noeviction is required')
        base=f'powgate:{{{args.namespace}}}'
        epoch=command(sock,'EVAL',SCRIPT,2,base+':epoch',base+':clock','rotate' if args.rotate else 'init',args.rotate or '',secrets.token_hex(32))
    if len(epoch)!=64 or any(c not in '0123456789abcdef' for c in epoch):raise RuntimeError('unexpected epoch')
    # Same file on every proxy. Replace atomically; nginx reads it during config.
    fd,name=tempfile.mkstemp(prefix='.pow-epoch-',dir=args.output.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(epoch+'\n')
        os.replace(name,args.output)
    finally:
        if os.path.exists(name):os.unlink(name)
    print(f'Epoch written to {args.output}; deploy the same file to every proxy and reload.')
if __name__=='__main__':main()
