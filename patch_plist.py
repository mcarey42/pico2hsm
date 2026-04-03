import plistlib
path = '/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist'
with open(path, 'rb') as f:
  d = plistlib.load(f)
vids = d['ifdVendorID']; pids = d['ifdProductID']; names = d['ifdFriendlyName']
if '0x1209' in vids and '0x27C0' in pids:
  idx = next(i for i,v in enumerate(vids) if v=='0x1209' and pids[i]=='0x27C0')
  names[idx] = 'pico2hsm SC-HSM'
  print('Updated existing entry')
else:
  idx = next((i for i,v in enumerate(vids) if v=='0x1209'), len(vids))
  vids.insert(idx, '0x1209'); pids.insert(idx, '0x27C0'); names.insert(idx, 'pico2hsm SC-HSM')
  for key in ('ifdSupportedClass','ifdCapabilities','ifdDriverOptions'):
    if key in d and isinstance(d[key], list) and len(d[key]) == len(vids)-1:
      d[key].insert(idx, d[key][max(0,idx-1)])
      print('Added new entry')
with open(path, 'wb') as f:
  plistlib.dump(d, f, fmt=plistlib.FMT_XML)
print('Done')
