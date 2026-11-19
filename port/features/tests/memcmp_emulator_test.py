#!/usr/bin/env python3
"""Test compiled ARM64 memcmp with Unicorn, including guard pages and FPSIMD.

Pass a compiled memcmp object, llvm-objcopy, and an isolated Unicorn package.
No emulator dependency is installed into the host environment by this test.
"""
import argparse
import ctypes
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", required=True)
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("--unicorn-path", required=True)
    args = parser.parse_args()
    sys.path.insert(0, args.unicorn_path)
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
    from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_Q0

    with tempfile.TemporaryDirectory(prefix="onyx-memcmp-code-") as tmp:
        code = Path(tmp) / "text.bin"
        subprocess.run([args.objcopy, "--dump-section", ".text=" + str(code),
                        args.object], check=True)
        data = code.read_bytes()
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x100000, 0x1000)
    uc.mem_write(0x100000, data)
    uc.mem_map(0x200000, 0x2000)
    uc.mem_map(0x300000, 0x2000)
    stop = 0x100800
    rng = random.Random(618)
    sizes = list(range(256)) + [257, 511, 512, 513, 1023, 1024, 1025, 4095, 4096]
    sizes += [rng.randrange(4097) for _ in range(500)]
    count = 0
    for size in sizes:
        for variation in range(5):
            left = bytes(rng.randrange(256) for _ in range(size))
            right = bytearray(left)
            if size and variation:
                index = [0, size - 1, size // 2, rng.randrange(size)][variation - 1]
                right[index] ^= 1 << rng.randrange(8)
            right = bytes(right)
            # End exactly at an unmapped page for guard-page cases. Other
            # cases vary each buffer's alignment independently.
            p1 = 0x202000 - size - (variation * 3)
            p2 = 0x302000 - size - (variation * 5)
            if size:
                uc.mem_write(p1, left)
                uc.mem_write(p2, right)
            uc.reg_write(UC_ARM64_REG_X0, p1)
            uc.reg_write(UC_ARM64_REG_X1, p2)
            uc.reg_write(UC_ARM64_REG_X2, size)
            uc.reg_write(UC_ARM64_REG_LR, stop)
            vectors = [rng.getrandbits(128) for _ in range(8)]
            for i, value in enumerate(vectors):
                uc.reg_write(UC_ARM64_REG_Q0 + i, value)
            uc.emu_start(0x100000, stop, count=100000)
            result = ctypes.c_int32(uc.reg_read(UC_ARM64_REG_X0)).value
            expected = (left > right) - (left < right)
            assert (result > 0) - (result < 0) == expected, (size, variation, result)
            assert all(uc.reg_read(UC_ARM64_REG_Q0 + i) == value
                       for i, value in enumerate(vectors)), "FPSIMD registers changed"
            count += 1
    print("ARM64 memcmp passed", count, "comparison/guard-page/FPSIMD cases")


if __name__ == "__main__":
    main()
