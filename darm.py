import argparse
from disassembler import ARMDisassembler
from binary import ARMBinary
import resource
import sys

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
        "-v",
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="print verbose output with instruction info",
    )
    # output folder
    parser.add_argument(
        "-d", "--output_dir", dest="output_dir", default="tmp", help="output directory"
    )
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()
    # print(args)

    if args.ground_truth:
        print("Generating ground truth for {}".format(args.filepath_input))
        b = ARMBinary(args.filepath_input, aarch=args.arch)
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
    resource.setrlimit(resource.RLIMIT_STACK, (2**29,-1))
    sys.setrecursionlimit(10**6)
    
    main()
