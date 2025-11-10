import ipfshttpclient

client = ipfshttpclient.connect("/ip4/127.0.0.1/tcp/5002/http")

cid = client.add_bytes(b"hello ipfs")
print(cid)
