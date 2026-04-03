import plistlib
path = '/etc/libccid_Info.plist'
with open(path, 'rb') as f:
  d = plistlib.load(f)
vids = d['ifdVendorID']; pids = d['ifdProductID']; names = d['ifdFriendlyName']
idx = max(i for i,v in enumerate(vids) if v == '0x1209') + 1
vids.insert(idx, '0x1209'); pids.insert(idx, '0x27C0'); names.insert(idx, 'pico2hsm SC-HSM')
for key in ('ifdSupportedClass','ifdCapabilities','ifdDriverOptions'):
  if key in d and isinstance(d[key], list) and len(d[key]) == len(vids)-1:
    d[key].insert(idx, d[key][idx-1])
with open(path, 'wb') as f:
  plistlib.dump(d, f, fmt=plistlib.FMT_XML)
print("done")
