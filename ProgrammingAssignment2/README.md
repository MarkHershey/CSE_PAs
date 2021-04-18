# ProgrammingAssignment2

Programming Assignment 2 for 50.005 Computer System Engineering at SUTD

---

-   PA2 briefing: https://docs.google.com/document/d/13ejwUagzpAMuWI91-uwWF1TswoJVLGW3Gd9i6Vq9IWs/edit

## Packet Type

| packetType (`int`) | Ref Name       | Packet Description     |
| :----------------: | :------------- | :--------------------- |
|        `0`         | `plainMsg`     | plain text message     |
|        `1`         | `encryptedMsg` | encrypted text message |
|        `2`         | `filename`     | encrypted filename     |
|        `3`         | `file`         | encrypted file content |
|        `99`        | `cert`         | CA-signed certificate  |
|        `98`        | `nonce`        | nonce                  |
|        `97`        | `pubKey`       | public key             |
|        `96`        | `sessionKey`   | encrypted session key  |

## Packet Schema

| packetType (`int`) | signed digest | payloadSize (`int`) | encrypted payload |
| :----------------: | :-----------: | :-----------------: | :---------------: |
|      4 Bytes       |   128 Bytes   |       4 Bytes       |      X Bytes      |

## Collaborators

-   [Daniel Low @nexaitch](https://github.com/nexaitch)
-   [Huang He @MarkHershey](https://github.com/MarkHershey)
