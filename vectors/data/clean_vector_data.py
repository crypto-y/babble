"""A simple python script to clean the vectors data.

Will create a new txt file with vector format, as defined in,
https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors#format

{
"vectors": [
    {
        "name": "free form description of handshake",
        "protocol_name": "<any valid handshake pattern name>",
        "hybrid": "25519|448|NewHope"
        "fail": false|true,
        "fallback": false|true,
        "fallback_pattern": "<any valid handshake pattern name>",
        "init_prologue": "hex string",
        "init_psks": ["hex string", ...]
        "init_static": "hex string",
        "init_ephemeral": "hex string",
        "init_remote_static": "hex string",
        "resp_prologue": "hex string",
        "resp_psks": ["hex string", ...]
        "resp_static": "hex string",
        "resp_ephemeral": "hex string",
        "resp_remote_static": "hex string",
        "handshake_hash": "hex string",
        "messages": [
            {
                "payload": "hex string",
                "ciphertext": "hex string"
            }, ...
        ]
    }, ...
]}
"""
import json

total = 0
vector_data = []
unique_names = set()
unique_ciphertext = set()


# process snow.txt, which has no handshake_hash
with open("./snow.txt") as f:
    data = json.load(f)
    print("snow", len(data["vectors"]))
    total += len(data["vectors"])
    for record in data["vectors"]:
        if record["protocol_name"] not in unique_names:
            unique_names.add(record["protocol_name"])
            vector_data.append(record)


# # process cacophony.txt
# with open("./cacophony.txt") as f:
#     data = json.load(f)
#     print("cacophony", len(data["vectors"]))
#     total += len(data["vectors"])
#     for record in data["vectors"]:
#         if record["protocol_name"] not in unique_names:
#             unique_names.add(record["protocol_name"])
#             vector_data.append(record)


# # process noise-c-basic.txt
# with open("./noise-c-basic.txt") as f:
#     data = json.load(f)
#     print("noise-c-basic", len(data["vectors"]))
#     total += len(data["vectors"])
#     for record in data["vectors"]:
#         # skip PSK
#         components = record["name"].split("_")
#         if components[0].endswith("PSK"):
#             continue

#         record["protocol_name"] = "_".join(components)
#         if record["protocol_name"] not in unique_names:
#             unique_names.add(record["protocol_name"])
#             vector_data.append(record)


print(
    "total: %s" % total,
    "unique names: %s" % len(unique_names),
    "unique records: %s" % len(vector_data)
)


with open("../vectors.txt", "w") as f:
    json.dump({"vectors": vector_data}, f, sort_keys=True, indent=4)
print("finished!")
