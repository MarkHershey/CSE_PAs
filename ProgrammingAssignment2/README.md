# Programming Assignment 2

Programming Assignment 2 for 50.005 Computer System Engineering at SUTD

<!-- -   PA2 briefing: https://docs.google.com/document/d/13ejwUagzpAMuWI91-uwWF1TswoJVLGW3Gd9i6Vq9IWs/edit -->

---

## How to run the code?

Step 1: Server's Terminal Window:

```bash
$ cd PA2
$ make
$ java ServerCP2
```

Step 2: Client's Terminal Window:

-   Interactive mode (to send multiple files)

    ```bash
    $ cd PA2
    $ java ClientCP2
    ```

-   Command line mode (to send a single file)

    ```bash
    $ cd PA2
    $ java ClientCP2 /path/to/your/file
    ```

## Packet Type

| packetType (`int`) | Ref Name        | Payload Description              |
| :----------------: | :-------------- | :------------------------------- |
|        `0`         | `plainMsg`      | plain text message               |
|        `1`         | `encryptedMsg`  | encrypted text message           |
|        `2`         | `filename`      | encrypted filename               |
|        `3`         | `file`          | encrypted file content           |
|        `11`        | `sEncryptedMsg` | (session) encrypted text message |
|        `12`        | `sFilename`     | (session) encrypted filename     |
|        `13`        | `sFile`         | (session) encrypted file content |
|        `99`        | `cert`          | CA-signed certificate            |
|        `98`        | `nonce`         | nonce                            |
|        `97`        | `pubKey`        | public key                       |
|        `96`        | `sessionKey`    | encrypted session key            |

## Packet Schema

Use public key encryption

|        | packetType (`int`) | signed digest | payloadSize (`int`) |     Payload     |
| ------ | :----------------: | :-----------: | :-----------------: | :-------------: |
| length |      4 Bytes       |   128 Bytes   |       4 Bytes       | variable length |

Use session key encryption

|        | packetType (`int`) |  digest  | payloadSize (`int`) |     Payload     |
| ------ | :----------------: | :------: | :-----------------: | :-------------: |
| length |      4 Bytes       | 32 Bytes |       4 Bytes       | variable length |

## Collaborators

-   [Daniel Low @nexaitch](https://github.com/nexaitch)
-   [Huang He @MarkHershey](https://github.com/MarkHershey)

```

```
