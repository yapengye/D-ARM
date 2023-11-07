import argparse
from disassembler import ARMDisassembler
from binary import ARMBinary
import resource
import sys
import subprocess


def get_parser():
    parser = argparse.ArgumentParser(description="Disassemble ARM binary")
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        dest="filepath_input",
        help="filepath of input binary",
    )
    parser.add_argument(
        "-a",
        "--arch",
        dest="arch",
        default=None,
        type=int,
        help="architecture of input binary (32 or 64)",
    )
    parser.add_argument(
        "-gt",
        "--ground_truth",
        dest="ground_truth",
        default=False,
        action="store_true",
        help="generate ground truth",
    )
    parser.add_argument(
        "-s",
        "--strip",
        dest="strip",
        default=False,
        action="store_true",
        help="strip binary before disassembly",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="print verbose output with instruction info",
    )
    parser.add_argument(
        "-o", "--output_dir", dest="output_dir", default="tmp", help="output directory"
    )
    return parser


def check_if_stripped(filepath):
    cmd = "file {}".format(filepath)
    output = subprocess.check_output(cmd, shell=True)
    output = output.decode("utf-8")
    print(output)
    if "not stripped" in output:
        return False
    else:
        return True


def main():
    parser = get_parser()
    args = parser.parse_args()
    # print(args)

    is_stripped = check_if_stripped(args.filepath_input)
    if not args.strip:
        args.strip = is_stripped

    if not args.strip:
        print("Generating ground truth for {}".format(args.filepath_input))
        b = ARMBinary(args.filepath_input, aarch=args.arch, is_stripped=False)
        b.generate_truth()
        b.print_ground_truth(details=args.verbose)
    else:
        darm = ARMDisassembler(
            args.filepath_input,
            aarch=args.arch,
            output_dir=args.output_dir,
            verbose=args.verbose,
        )
        results = darm.disassemble()
        darm.print_results(results, args.verbose)


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_STACK, (2**29, -1))
    sys.setrecursionlimit(10**6)

    main()
