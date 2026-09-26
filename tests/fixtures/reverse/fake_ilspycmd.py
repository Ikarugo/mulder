#!/usr/bin/env python3
"""Stand-in for ilspycmd: copies the fixture C# project or IL to -o.

Mirrors the command-line shape mulder uses: ilspycmd <asm> -p -o <dir>
(C# project) and ilspycmd <asm> -il -o <dir> (IL). A sample whose name
starts with "native" fails like a non-.NET file does.
"""

import shutil
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "ilspy"
args = sys.argv[1:]
out = Path(args[args.index("-o") + 1])
if Path(args[0]).name.startswith("native"):
    print(
        "ICSharpCode.Decompiler.Metadata.MetadataFileNotSupportedException: "
        "PE file does not contain any managed metadata.",
        file=sys.stderr,
    )
    sys.exit(70)
src = FIXTURE / ("il" if "-il" in args else "csharp")
shutil.copytree(src, out, dirs_exist_ok=True)
