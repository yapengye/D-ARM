# D-ARM

D-ARM is a disassembler particularly designed for ARM binaries. It features a lightweight superset static analysis to derive rich semantic information and a graph-theory based method that aggregates such information to produce disassembly results. 
Please find the details in our [paper](https://www.cs.purdue.edu/homes/ye203/pub/SP23.pdf).

This repo is WIP. 

## Requirements
- Python 3.6 or higher
- Install dependencies:
```bash
$ pip install -r requirements.txt
```

## Usage
Run D-ARM with the following command:
```bash
python darm.py -i PATH_TO_BINARY [Other Options]
```
e.g.:
```bash
python darm.py -i test/binary/spec2000_gcc5.5_O0_marm_v5t_bzip2
```
Arguments:
- `-i`, `--input`: the filepath of input binary (required)
- `-a`, `--arch`: architecture of input binary (32 or 64) (default: identify the architecture automatically)
- `-v`, `--verbose`: print verbose output with instruction info (default: False)
- `-s`, `--strip`: strip binary before disassembly (default: False)
- `-o`, `--output_dir`: the folder for output files
<!-- - `-gt`, `--ground_truth`: generate the ground truth for unstripped binaries if it is set -->


## Cite
+ Yapeng Ye, Zhuo Zhang, Qingkai Shi, Yousra Aafer, Xiangyu Zhang. "D-ARM: Disassembling ARM Binaries by Lightweight Superset Instruction Interpretation and Graph Modeling." In 2023 IEEE Symposium on Security and Privacy (SP).