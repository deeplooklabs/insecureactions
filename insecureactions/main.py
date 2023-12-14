import sys
from .checkactions import check

def main():
    if len(sys.argv) > 1:
        org_name = sys.argv[1]
        check(org_name)
    else:
        print("Please send the org name:\nEx: $ insecureactions uber")

if __name__ == "__main__":
    main()
