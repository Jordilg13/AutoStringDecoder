#!/usr/bin/env python3

import sys
import getopt
import argparse
from base64 import *
import morse_talk as mtalk
import binascii
import pprint
from base58 import *

# PARSER
parser = argparse.ArgumentParser(prog="decoder.py", usage=None, description="Autodecode encrypted messages using all supported methods", epilog=None, parents=[
], formatter_class=argparse.HelpFormatter, prefix_chars='-', fromfile_prefix_chars=None, argument_default=None, conflict_handler='error', add_help=True, allow_abbrev=True)

# ARGUMENTS
file_string = parser.add_mutually_exclusive_group(required=False)
file_string.add_argument("-s", "--string", help="Encrypted string")
file_string.add_argument(
    "-f", "--file", help="File that contain the encrypted string")
parser.add_argument("-a", "--all", action='store_false',
                    help="Bruteforce all methods",)

parsed = parser.parse_args(sys.argv[1:])


def bruteforce(string):
    results = {}
    # BASES
    base = {16: b16decode, 32: b32decode, 58:b58decode, 64: b64decode, 85: b85decode}
    for i in base.keys():
        try:
            results['b'+str(i)] = base[i](string)
        except:
            pass
            # print("error base: "+str(i))

    # MORSE
    try:
        results['morse'] = mtalk.decode(string)
    except Exception as e:
        pass

    # HEX
    try:
        results['hex'] = bytearray.fromhex(string).decode()
    except Exception as e:
        pass

    # BINARY, OCTAL, DECIMAL
    for base in [2,8,10]:
        try:
            results['base-'+str(base)] = "".join([chr(int(i,base=base)) for i in string.split()])
        except Exception as e:
            pass

    print()
    pprint.pprint(results)
    print()



def main(args):
    if len(sys.argv[1:]) < 1:
        parser.print_help()
    elif not args.all:
        bruteforce(args.string)


if __name__ == "__main__":
    main(parsed)
