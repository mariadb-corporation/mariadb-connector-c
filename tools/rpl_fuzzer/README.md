# Replication Fuzzer (`rpl_fuzzer`)

This directory contains the `rpl_fuzzer` target, an LLVM-based coverage-guided fuzzing harness designed to test the stability and security of the MariaDB replication stream parser and row extraction logic.

---

## Code Coverage Architecture

The fuzzer is strategically designed to parse multi-layered replication protocol sequences. It automatically handles structural dependencies by pinning state-machine contexts across event processing iterations.

```text
       +-----------------------+
       |   Fuzzer Byte Stream  |
       +-----------------------+
                   |
                   v (Dynamic Magic Byte Alignment)
       +-----------------------+
       |   \xFEbin Binlog Head |
       +-----------------------+
                   |
                   v
       +-----------------------+
       |   TABLE_MAP_EVENT     |-----> [Pins Metadata State Context]
       +-----------------------+                       |
                   |                                   |
                   v                                   v
       +-----------------------+           +-----------------------+
       |   WRITE_ROWS_EVENT    |---------->| mariadb_rpl_extract   |
       |  (or Update / Delete) |           |         _rows()       |
       +-----------------------+           +-----------------------+
                                                       |
                                                       v
                                            [Deep Column Decoders]
```

---

## Corpus Directory Initialization

To ensure high-efficiency fuzzing from execution count #1, the `data/` corpus directory must be populated with authentic MariaDB binary log files containing a rich diversity of event structures (Statement-Based Replication, Row-Based Replication, and Compressed Events).

Instead of committing massive binary logs directly to the repository, you can generate fresh, highly specific seed files using the integrated MariaDB test suite environment (ctest).

---

## Step-by-Step Seed Generation

### 1. Create the target data and corpus folder

```bash
mkdir -p data/
mkdir -p corpus/
```

---

### 2. Generate Replication Seeds
To get better coverage run the unittest suite both against MySQL and MariaDB servers.

#### SBR (Statement based replication)

Change your server settings to statement based replication (binlog_format=Statement), flush your logs and
run the unittest suite. Afterwards copy the binlog files to the data folder and rename it.

#### RBR (Row based replication)

Change your server settings to statement based replication (binlog_format=Row), flush your logs and
run the unittest suite. Afterwards copy the binlog files to the data folder and rename it.

#### Compressed Row/Query Seeds

For both SBR and RBR set the global variable binlog_compression to ON, run the unittest suite and copy
the binlog files to the data folder and rename it.



## Running the Fuzzer

Once the `data/` folder contains your valid seeds, you can unleash the fuzzer across multiple cores.

For high-core systems use the following configuration to deploy 10 parallel background workers while maintaining operating system stability:

```bash
./rpl_fuzzer -max_len=131072 -workers=10 -jobs=10 $(pwd)/corpus $(pwd)/data/
```

---

## Monitoring Progress

To monitor the real-time throughput, code coverage (`cov:`), and state feature tracking (`ft:`) of your parallel processing cluster, execute:

```bash
tail -n 1 fuzz-*.log
```

