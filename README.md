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
Usage: ./ton-msigd [OPTIONS] [addr] SUBCOMMAND

Positionals:
  addr ADDRESS:ADDRESS                    Wallet contract address

Options:
  -h,--help                               Print this help message and exit
  -v,--verbose INT=3                      Verbosity level
  -t,--threads UINT:POSITIVE=2            Thread count
  -c,--config TEXT:FILE                   Path to global config

Subcommands:
  generate                                Generate new keypair
  submitTransaction                       Create new transaction
  confirmTransaction                      Confirm pending transaction
  isConfirmed                             Check if transactions are confirmed
  getParameters                           Get msig parameters
  getTransaction                          Get transaction info
  getTransactions                         Get pending transactions
  getTransactionIds                       Get ids of pending transactions
  getCustodians                           Get owners of this wallet
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
    -DMSIG_WITH_API=OFF \
    -DTON_USE_GDB=OFF \
    -DTON_USE_STACKTRACE=OFF

# Build project
cmake --build . --target ton-msig -- -j4

# Done
./bin/ton-msig -h
```
