import asyncio
from pathlib import Path

from openharness.tools.bash_tool import BashTool, BashToolInput


class Context:
    cwd = Path(".")


async def main():
    marker = Path("/tmp/pub_guard_marker")
    marker.mkdir(parents=True, exist_ok=True)
    (marker / "alive.txt").write_text("alive\n", encoding="utf-8")

    result = await BashTool().execute(
        BashToolInput(command="rm -rf /tmp/pub_guard_marker"),
        Context(),
    )

    print("is_error=", result.is_error)
    print("output=")
    print(result.output)
    print("metadata=")
    print(result.metadata)
    print("marker_exists=", (marker / "alive.txt").exists())
    if (marker / "alive.txt").exists():
        print("marker_content=", (marker / "alive.txt").read_text(encoding="utf-8").strip())


asyncio.run(main())
