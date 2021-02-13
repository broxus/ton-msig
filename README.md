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
    <p align="center"><a href="https://github.com/broxus/ton-msig/wiki">Wiki</a></p>
</p>

### Usage
```
ton-msig
Usage: ./ton-msig [OPTIONS] [addr] SUBCOMMAND

Positionals:
  addr ADDRESS:ADDRESS                       Wallet contract address

Options:
  -h,--help                                  Print this help message and exit
  --help-all                                 Print extended help message and exit
  -v,--version                               Display program version information and exit
  -l,--log-level INT:INT in [1 - 7]=3        Log verbosity level
  -t,--threads UINT:POSITIVE=2               Thread count
  -c,--config TEXT:FILE                      Path to global config

Subcommands:
convert
  Convert address into another formats

getpubkey
  Get public key from private
  Positionals:
    privkey TEXT:KEY REQUIRED                  Private key hex

gensignature
  Sign tree of cells
  Positionals:
    cells TEXT                                 Hex encoded serialized tree of cells
  Options:
    -s,--sign TEXT:(FILE) OR (PHRASE) REQUIRED Mnemonic or path to keypair file

generate
  Generate new keypair and address
  Options:
    -a,--addr BOOLEAN=1                        Whether to generate an address
    -w,--workchain INT:INT in [-1 - 0]         Workchain
    -f,--from TEXT:(FILE) OR (PHRASE)          Mnemonic or path to keypair file

mine
  Mine pretty address
  Positionals:
    prefix TEXT REQUIRED                       Target address prefix in hex format

deploy
  Deploy new contract
  Options:
    -s,--sign TEXT:(FILE) OR (PHRASE) REQUIRED Mnemonic or path to keypair file
    -w,--workchain INT:INT in [-1 - 0]         Workchain
    -o,--owner TEXT:KEY ... REQUIRED           Custodian public key
    -r,--req-confirms UINT:INT in [1 - 32]=1   Number of confirmations required for executing transaction
    --timeout UINT:INT in [10 - 86400]=60      Set message expiration timeout in seconds
    --save TEXT                                Save message info to file

info
  Get account info

find
  Find entity by id
  Subcommands:
    message                                    Find message by hash

submitTransaction
  Create new transaction
  Positionals:
    dest TEXT:ADDRESS REQUIRED                 Destination address
    value TEXT:TON REQUIRED                    Message value in TON
  Options:
    --all-balance BOOLEAN=0                    Send all balance and delete contract
    --bounce BOOLEAN=1                         Return message back when it is send to uninitialized address
    --payload TEXT                             Serialized bag of cells of message body
    -s,--sign TEXT:(FILE) OR (PHRASE) REQUIRED Mnemonic or path to keypair file
    --local                                    Force local execution
    --timeout UINT:INT in [10 - 86400]=60      Set message expiration timeout in seconds
    --save TEXT                                Save message info to file

confirmTransaction
  Confirm pending transaction
  Positionals:
    transactionId UINT REQUIRED                Transaction id
  Options:
    -s,--sign TEXT:(FILE) OR (PHRASE) REQUIRED Mnemonic or path to keypair file
    --local                                    Force local execution
    --timeout UINT:INT in [10 - 86400]=60      Set message expiration timeout in seconds
    --save TEXT                                Save message info to file

isConfirmed
  Check if transactions are confirmed
  Positionals:
    mask UINT:POSITIVE REQUIRED                Mask
    index UINT:POSITIVE REQUIRED               Index

getParameters
  Get msig parameters

getTransaction
  Get transaction info
  Positionals:
    transactionId UINT:POSITIVE REQUIRED       Transaction id

getTransactions
  Get pending transactions

getTransactionIds
  Get ids of pending transactions

getCustodians
  Get owners of this wallet
```

### Docker

```shell
git clone https://github.com/broxus/ton-msig.git --recursive
cd ton-msig
docker build -t broxus/ton-msig .
alias ton-msig="docker run --rm -it broxus/ton-msig"
ton-msig --help-all
```

### Building

> * requires the latest CMake (e.g. 3.18)
> * g++ > 7.4.0
> * libssl-dev, zlib1g-dev

```
# Prepare project
git clone https://github.com/broxus/ton-msig.git --recursive
mkdir -p ton-msig/build
cd ton-msig/build

# Configure project
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DTON_USE_ROCKSDB=OFF \
    -DTON_USE_ABSEIL=OFF \
    -DTON_USE_GDB=OFF \
    -DTON_USE_STACKTRACE=OFF

# Build project
cmake --build . --target ton-msig -- -j4

# Done
./bin/ton-msig -v
```
