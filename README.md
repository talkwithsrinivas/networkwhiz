# networkwhiz
Network (W)viz on Linux

## Env Setup
This project uses eunomia development framewok and the dev env can be setup by following steps at https://eunomia.dev/en/tutorials/1-helloworld/

Summarizing the steps here. Below was tested on ubunut22.04.

0) sudo apt install clang llvm

1) wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli

  $ ./ecli -h
  Usage: ecli [--help] [--version] [--json] [--no-cache] url-and-args

2) wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc

  $ ./ecc -h
  eunomia-bpf compiler
  Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]

