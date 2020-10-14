<p align="center">
    <h3 align="center">ton-msig</h3>
    <p align="center">Tool for TON multisignature wallets</p>
    <p align="center">
        <a href="/LICENSE">
            <img alt="GitHub" src="https://img.shields.io/github/license/broxus/ton-msig" />
        </a>
        <a href="https://github.com/broxus/ton-msig/actions?query=workflow%3Amaster">
            <img alt="GitHub Workflow Status" src="https://img.shields.io/github/workflow/status/broxus/ton-msig/master" />
        </a>
    </p>
</p>

### Usage
```
ton-msig
Usage: ./ton-msig [OPTIONS] [addr] SUBCOMMAND

Positionals:
  addr ADDRESS:ADDRESS                      Wallet contract address

Options:
  -h,--help                                 Print this help message and exit
  --help-all                                Print extended help message and exit
  -v,--verbose INT:INT in [1 - 6]=3         Verbosity level
  -t,--threads UINT:POSITIVE=2              Thread count
  -c,--config TEXT:FILE                     Path to global config

Subcommands:
convert
  Convert address into another formats

generate
  Generate new keypair
  Options:
    -a,--addr                                 Whether to generate an address
    -w,--workchain INT:INT in [-1 - 0]        Workchain
    -f,--from TEXT:FILE                       Path to keypair file

deploy
  Deploy new contract
  Options:
    -s,--sign TEXT:FILE REQUIRED              Path to keypair file
    -w,--workchain INT:INT in [-1 - 0]        Workchain
    -o,--owner TEXT:PUBKEY ... REQUIRED       Custodian public key
    -r,--req-confirms UINT:INT in [1 - 32]=1  Number of confirmations required for executing transaction

info
  Get account info

submitTransaction
  Create new transaction
  Positionals:
    dest TEXT:ADDRESS REQUIRED                Destination address
    value TEXT:TON REQUIRED                   Message value in TON
  Options:
    --all-balance BOOLEAN=0                   Send all balance and delete contract
    --bounce BOOLEAN=1                        Return message back when it is send to uninitialized address
    --payload TEXT                            Serialized bag of cells of message body
    -s,--sign TEXT:FILE REQUIRED              Path to keypair file
    --local                                   Force local execution

confirmTransaction
  Confirm pending transaction
  Positionals:
    transactionId UINT REQUIRED               Transaction id
  Options:
    -s,--sign TEXT:FILE REQUIRED              Path to keypair file
    --local                                   Force local execution

isConfirmed
  Check if transactions are confirmed
  Positionals:
    mask UINT:POSITIVE REQUIRED               Mask
    index UINT:POSITIVE REQUIRED              Index

getParameters
  Get msig parameters

getTransaction
  Get transaction info
  Positionals:
    transactionId UINT:POSITIVE REQUIRED      Transaction id

getTransactions
  Get pending transactions

getTransactionIds
  Get ids of pending transactions

getCustodians
  Get owners of this wallet
```

### Building
```
# Install dependencies
sudo apt-get update
sudo apt-get install git gcc g++ make libssl-dev zlib1g-dev wget

# Install latest version of cmake
wget -qO- "https://cmake.org/files/v3.18/cmake-3.18.4-Linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C ~/.local

# Clone project
git clone https://github.com/broxus/ton-msig.git --recursive
mkdir -p ton-msig/build
cd ton-msig/build

# Configure project
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DTON_USE_ROCKSDB=OFF \
    -DTON_USE_ABSEIL=OFF \
    -DMSIG_WITH_API=OFF \
    -DTON_USE_GDB=OFF \
    -DTON_USE_STACKTRACE=OFF

# Build project
cmake --build . --target ton-msig -- -j4

# Done
./bin/ton-msig -h
```
