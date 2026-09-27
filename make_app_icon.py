#!/usr/bin/env python3
"""Recolor the installed Train at Home app mark and package it as AppIcon.icns."""
from pathlib import Path
import struct
import zlib
from PIL import Image

ROOT=Path(__file__).resolve().parent
SOURCE=Image.open(ROOT/"TAHIconSource.png").convert("RGBA")
if SOURCE.size != (1024,1024):
    SOURCE=SOURCE.resize((1024,1024),Image.Resampling.LANCZOS)

# TAH's original white/gray loop mark, retaining its shape and transparency,
# with a black-green ground and Matrix-green light.
pixels=SOURCE.load()
for y in range(1024):
    for x in range(1024):
        r,g,b,a=pixels[x,y]
        if a==0:
            continue
        luminance=(r*299+g*587+b*114)//1000
        strength=max(0.0,min(1.0,(luminance-17)/231.0))
        strength=strength**0.88
        pixels[x,y]=(round(1+3*strength),round(5+250*strength),round(3+99*strength),a)

ICONSET=ROOT/"AppIcon.iconset"
ICONSET.mkdir(exist_ok=True)
entries=[("icon_16x16.png",16),("icon_16x16@2x.png",32),("icon_32x32.png",32),("icon_32x32@2x.png",64),("icon_128x128.png",128),("icon_128x128@2x.png",256),("icon_256x256.png",256),("icon_256x256@2x.png",512),("icon_512x512.png",512),("icon_512x512@2x.png",1024)]
for filename,size in entries:
    SOURCE.resize((size,size),Image.Resampling.LANCZOS).save(ICONSET/filename)

def chunk(kind,data):
    return struct.pack(">I",len(data))+kind+data+struct.pack(">I",zlib.crc32(kind+data)&0xffffffff)
parts=[]
for code,filename in [(b"icp4","icon_16x16.png"),(b"icp5","icon_32x32.png"),(b"icp6","icon_32x32@2x.png"),(b"ic07","icon_128x128.png"),(b"ic08","icon_256x256.png"),(b"ic09","icon_512x512.png"),(b"ic10","icon_512x512@2x.png")]:
    data=(ICONSET/filename).read_bytes()
    parts.append(code+struct.pack(">I",len(data)+8)+data)
body=b"".join(parts)
(ROOT/"AppIcon.icns").write_bytes(b"icns"+struct.pack(">I",len(body)+8)+body)
resources=ROOT/"pkg-resources"
resources.mkdir(exist_ok=True)
(resources/"PackageIcon.icns").write_bytes((ROOT/"AppIcon.icns").read_bytes())
SOURCE.resize((512,512),Image.Resampling.LANCZOS).save(resources/"PackageIcon.png")
print(f"Created Matrix-green TAH icon at {ROOT/'AppIcon.icns'}")
