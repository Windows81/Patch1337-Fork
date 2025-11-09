#!/usr/bin/env python
"""Patches files based on 1337 patch files."""

import dataclasses
import functools
import io
import pefile
import binascii
import shutil
import sys
from pathlib import Path

import click
from loguru import logger

__version__ = "0.5.1"


@click.command()
@click.help_option("-h", "--help")
@click.option(
    "-p",
    "--patch",
    required=True,
    multiple=True,
    default=[
        "nvencodeapi.1337",
        "nvencodeapi64.1337",
    ],
    help="Filename(s) of .1337 patch(es)",
)
@click.option(
    "-t",
    "--target",
    required=True,
    multiple=True,
    default=[
        "nvEncodeAPI.dll",
        "nvEncodeAPI64.dll",
    ],
    help="Filename(s) of target file(s).",
)
@click.option(
    "-o",
    "--offset",
    type=click.UNPROCESSED,
    callback=lambda ctx, param, value: tuple(
        int(v, base=16) if isinstance(v, str) else None for v in value
    ),
    required=False,
    multiple=True,
    default=[
        0xC00,
        0xC00,
    ],
    help="Manually apply offset in hex (calculates offset from RVA tables if not provided by default).",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Increase verbosity of output.",
)
@click.pass_context
def main(context: click.Context, **_) -> None:
    """Patches files based on 1337 patch files."""
    set_logging(context)
    patch = context.params["patch"]
    target = context.params["target"]
    offset = context.params["offset"]
    combinations = zip(patch, target, offset)
    for params in combinations:
        patcher(*params)


def set_logging(context: click.core.Context) -> None:
    """Set logging level."""
    level = "INFO"
    if context.params["verbose"]:
        level = "DEBUG"
    logger.configure(
        handlers=[
            {"sink": sys.stdout, "format": "{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}", "level": level},
        ],
    )


def check_patch(patch_file: str) -> bool:
    """Check validity of patch file."""
    with Path(patch_file).open() as header:
        if not header.readline().startswith(">"):
            logger.error(
                "{} is not a valid .1337 patch file",
                Path(patch_file).name,
            )
            return False
        logger.debug(
            "{} is a valid .1337 patch file",
            Path(patch_file).name,
        )
        return True


@functools.cache
def get_pe_sections(target: str) -> list[tuple[int, int, int]]:
    """Get the sections of a PE file."""
    pe = pefile.PE(target, fast_load=True)
    return [
        (
            section.VirtualAddress,
            section.VirtualAddress + section.Misc_VirtualSize,
            section.VirtualAddress - section.PointerToRawData,
        )
        for section in pe.sections
    ]


def rva_to_file_offset(target: str, rva: int) -> int:
    """Find the appropriate section for the given RVA"""
    for (start, end, offset) in get_pe_sections(target):
        if start <= rva < end:
            return rva - offset
    raise ValueError(f"RVA {rva} not found in any section of the PE file.")


def backup_file(target: str) -> bool:
    """Backup original target file."""
    backup_path = target + ".BAK"

    if Path(backup_path).exists():
        check = input(
            "Backup file exists, would you like to overwrite? (y/n/X): ",
        )
        if check.lower() == "y":
            pass
        elif check.lower() == "n":
            return True
        else:
            return False

    shutil.copy(Path(target), Path(backup_path))
    logger.info("Created backup of {}", Path(target).name)
    return True


@dataclasses.dataclass
class patch_info:
    loc: int = 0
    fr: int = 0
    to: int = 0


def parse(line: str, target: str, manual_offset: int | None) -> patch_info:
    """Parse a line from the patch file."""

    (rva_str, patch_str) = line.strip().split(":")
    (patch_from_str, patch_to_str) = patch_str.split("->")
    rva_val = int(rva_str, base=16)

    location = (
        rva_val - manual_offset
        if manual_offset is not None
        else rva_to_file_offset(target, rva_val)
    )
    return patch_info(
        loc=location,
        fr=int(patch_from_str, base=16),
        to=int(patch_to_str, base=16),
    )


def apply_patches(target_file: io.FileIO, patches: list[patch_info]) -> bool:
    """Apply patches to the target file."""

    is_normal_patch = True
    is_reverse_patch = True
    for patch in patches:
        logger.debug(
            "Patching 0x{:X} from {} to {}",
            patch.loc,
            patch.fr,
            patch.to,
        )
        logger.debug(
            "Checking patch at 0x{:X}",
            patch.loc,
        )
        target_file.seek(patch.loc)
        [unpatched_bit] = target_file.read(1)
        if is_normal_patch and unpatched_bit != patch.fr:
            is_normal_patch = False
        if is_reverse_patch and unpatched_bit != patch.to:
            is_reverse_patch = False

        if is_normal_patch or is_reverse_patch:
            continue

        logger.error(
            "Offset 0x{:X} was expected to be {} but was {} instead",
            patch.loc,
            patch.fr,
            unpatched_bit,
        )
        return False

    if is_reverse_patch:
        check = input(
            "All bits in the patch were already applied, would you like to reverse? (y/N): ",
        )
        if check.lower() != "y":
            return False

        for patch in patches:
            v = patch.fr
            target_file.seek(patch.loc)
            target_file.write(bytes([v]))

            logger.debug(
                "0x{:X} has been unpatched correctly to {}",
                patch.loc,
                v,
            )
    else:
        for patch in patches:
            v = patch.to
            target_file.seek(patch.loc)
            target_file.write(bytes([v]))

            logger.debug(
                "0x{:X} has been patched correctly to {}",
                patch.loc,
                v,
            )

    return True


def patcher(patch_path: str, target: str, manual_offset: int | None) -> None:
    if not Path(patch_path).exists() or not Path(target).exists():
        logger.error("{} or {} no longer exist", patch_path, target)
        return
    if not check_patch(patch_path):
        return
    if not backup_file(target):
        return

    with Path(patch_path).open() as patch_file:
        [first_line, *patch_lines] = patch_file.readlines()
        patch_target = first_line[1:].strip().lower()
        target_filename = Path(target).name

    if patch_target != target_filename.lower():
        logger.error(
            "The .1337 patch is not valid for the selected file ({}) but you selected ({})",
            str(first_line)[1:].lower(),
            target_filename,
        )
        return

    patches = [
        parse(line, target, manual_offset)
        for line in patch_lines
    ]

    with Path(target).open(mode="r+b", buffering=0) as target_file:
        apply_patches(target_file, patches)


if __name__ == "__main__":
    main()
