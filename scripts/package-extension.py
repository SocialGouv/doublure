#!/usr/bin/env python3
"""Build a .vsix from extension/, with the standard library alone.

A .vsix is a ZIP with a fixed layout — a manifest, a content-type map, and the
extension under `extension/`. Building it here rather than with `vsce` keeps
one dependency out of the toolchain and, more to the point, keeps the build
offline: this project's whole premise is that nothing leaves without passing
the proxy, and fetching a packager to publish a confidentiality tool would be
a poor way to start.

The manifest is DERIVED from package.json. Retyped, the two would disagree —
and the one that decides what the IDE installs is not the one you read.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "extension"
DIST = ROOT / "dist"

CONTENT_TYPES = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="xml" ContentType="text/xml"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="txt" ContentType="text/plain"/>
</Types>
"""

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0"
    xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"
    xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="{name}" Version="{version}" Publisher="{publisher}"/>
    <DisplayName>{display}</DisplayName>
    <Description xml:space="preserve">{description}</Description>
    <Tags/>
    <Categories>{categories}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{engine}"/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value=""/>
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value=""/>
    </Properties>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
  </Assets>
</PackageManifest>
"""

#: Everything the extension needs at run time, and nothing else. An explicit
#: list rather than a walk: a package built by sweeping a directory ships
#: whatever happens to be lying in it.
FILES = ("package.json", "extension.js", "README.md", "LICENSE")


def main() -> int:
    manifest = json.loads((SOURCE / "package.json").read_text(encoding="utf-8"))
    body = MANIFEST.format(
        name=escape(manifest["name"]),
        version=escape(manifest["version"]),
        publisher=escape(manifest["publisher"]),
        display=escape(manifest.get("displayName", manifest["name"])),
        description=escape(manifest.get("description", "")),
        categories=escape(",".join(manifest.get("categories", ["Other"]))),
        engine=escape(manifest["engines"]["vscode"]),
    )

    DIST.mkdir(exist_ok=True)
    target = DIST / f"{manifest['publisher']}.{manifest['name']}-{manifest['version']}.vsix"
    shipped = []
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as vsix:
        vsix.writestr("[Content_Types].xml", CONTENT_TYPES)
        vsix.writestr("extension.vsixmanifest", body)
        for name in FILES:
            path = SOURCE / name
            if not path.exists():
                continue
            vsix.write(path, f"extension/{name}")
            shipped.append(name)

    if "package.json" not in shipped or "extension.js" not in shipped:
        target.unlink(missing_ok=True)
        print("ABORT: the manifest or the entry point is missing from "
              f"{SOURCE} — an unusable package is worse than none.",
              file=sys.stderr)
        return 1

    print(f"{target}  ({target.stat().st_size} bytes, {', '.join(shipped)})")
    print()
    print("Install it with:")
    print(f"  codium --install-extension {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
