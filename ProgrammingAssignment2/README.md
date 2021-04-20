# Secure File Transfer

Programming Assignment 2 for 50.005 Computer System Engineering at SUTD

<!-- -   PA2 briefing: https://docs.google.com/document/d/13ejwUagzpAMuWI91-uwWF1TswoJVLGW3Gd9i6Vq9IWs/edit -->

---

## Prerequisites

JDK (JRE + JVM) is required, following commands should be available at PATH:

- `java`
- `javac`
- `make`

## Compile the code

Compile

```bash
$ cd PA2
$ make
```

Clean up

```bash
$ cd PA2
$ make clean
```

## How to run the code?

Step 1: Server's Terminal Window:

```bash
$ cd PA2
$ make
$ java ServerCP2
```

Step 2: Client's Terminal Window:

- Interactive mode (to send multiple files)

  ```bash
  $ cd PA2
  $ java ClientCP2
  ```

- Command line mode (to send a single file)

  ```bash
  $ cd PA2
  $ java ClientCP2 /path/to/your/file
  ```

## Specifications

- Please checkout the [Report](Report.md) for implementation and performance details.

## Collaborators

- [Daniel Low @nexaitch](https://github.com/nexaitch)
- [Huang He @MarkHershey](https://github.com/MarkHershey)
