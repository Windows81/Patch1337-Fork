#!/usr/bin/python
'''Patches files based on 1337 patch files.'''

import argparse
import dataclasses
import functools
import io
import pefile
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def get_patch_data(patch_file_path: Path) -> dict[str, list[str]] | None:
    '''Check validity of patch file.'''
    result = {}
    target_name = None
    with patch_file_path.open() as patch_file:
        for line in patch_file:

            if line.startswith('>'):
                target_name = line[1:].strip().lower()
                continue

            elif target_name is None:
                return None

            result.setdefault(target_name, []).append(line)

        return result


@functools.cache
def get_pe_sections(target: str) -> list[tuple[int, int, int]]:
    '''Get the sections of a PE file.'''
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
    '''Find the appropriate section for the given RVA'''
    for (start, end, offset) in get_pe_sections(target):
        if start <= rva < end:
            return rva - offset
    raise ValueError(f'RVA {rva} not found in any section of the PE file.')


def maybe_backup_file(target_path: Path) -> bool:
    '''Backup original target file.'''
    backup_path = target_path.with_name(target_path.name + '.BAK')

    if backup_path.exists():
        check = input(
            'Backup file exists; would you like to overwrite? (y/n/X): ',
        ).lower()
        match check:
            case 'y':
                pass
            case 'n':
                return True
            case _:
                return False

    shutil.copy(target_path, backup_path)
    logger.info('Created backup of %s' % target_path.name)
    return True


@dataclasses.dataclass
class patch_info:
    loc: int = 0
    fr: int = 0
    to: int = 0


def parse(line: str, target: str, reverse: bool = False) -> patch_info:
    '''Parse a line from the patch file.'''

    (rva_str, patch_str) = line.strip().split(':')
    (patch_from_str, patch_to_str) = patch_str.split('->')
    rva_val = int(rva_str, base=16)

    if reverse:
        (patch_from_str, patch_to_str) = (patch_to_str, patch_from_str)

    return patch_info(
        loc=rva_to_file_offset(target, rva_val),
        fr=int(patch_from_str, base=16),
        to=int(patch_to_str, base=16),
    )


def apply_patches(target_file: io.FileIO, patches: list[patch_info], try_reverse: bool = False) -> bool:
    '''Apply patches to the target file.'''

    is_normal_patch = True
    is_reverse_patch = try_reverse
    for patch in patches:
        target_file.seek(patch.loc)

        [unpatched_bit] = target_file.read(1)
        logger.debug(
            'Checking to patch 0x%X : 0x%02X > 0x%02X [now 0x%02X]' %
            (patch.loc, patch.fr, patch.to, unpatched_bit)
        )

        is_normal_patch &= bool(unpatched_bit == patch.fr)
        is_reverse_patch &= bool(unpatched_bit == patch.to)

        if is_normal_patch or is_reverse_patch:
            continue

        logger.error(
            'Offset 0x%X was expected to be 0x%02X but was 0x%02X instead' %
            (patch.loc, patch.fr, unpatched_bit)
        )
        return False

    match (is_normal_patch, is_reverse_patch):

        # Edge case for when the patch file is either empty or full of redundant patches (such as AB->AB).
        case (True, True):
            return True

        case (True, False):
            for patch in patches:
                v = patch.to
                target_file.seek(patch.loc)
                target_file.write(bytes([v]))

                logger.debug(
                    '0x%X has been patched correctly to 0x%02X' %
                    (patch.loc, v)
                )
            return True

        case (False, True):
            check = input(
                'All bits in the patch were already applied; would you like to reverse? (y/N): ',
            )
            if check.lower() != 'y':
                return False

            for patch in patches:
                v = patch.fr
                target_file.seek(patch.loc)
                target_file.write(bytes([v]))

                logger.debug(
                    '0x%X has been unpatched correctly to 0x%02X' %
                    (patch.loc, v)
                )
            return True

        # Execution should never go here.
        case _:
            assert False


def patcher(
    patch_path_str: str,
    target_path_str: str,
    try_normal: bool = True,
    try_reverse: bool = False,
    should_backup: bool = True,
) -> bool:
    patch_path = Path(patch_path_str)
    target_path = Path(target_path_str)

    if try_normal == False and try_reverse == False:
        return True

    if not patch_path.exists() or not target_path.exists():
        logger.error(
            '%s or %s do not exist' %
            (patch_path_str, target_path_str)
        )
        return False

    patch_data = get_patch_data(patch_path)
    if patch_data is None:
        logger.error('%s is not a valid .1337 patch file' % patch_path.name)
        return False

    target_filename = target_path.name.lower()
    patch_lines = patch_data.get(target_filename)

    if patch_lines is None:
        logger.error(
            'The .1337 patch is not valid for the selected file (%s)' % target_filename
        )
        return False

    logger.debug(
        '%s is a valid .1337 patch file' % patch_path.name
    )

    if should_backup and not maybe_backup_file(target_path):
        return False

    reverse_patches = (try_normal == False and try_reverse == True)
    try_both = (try_normal == True and try_reverse == True)

    patches = [
        parse(line, target_path_str, reverse_patches)
        for line in patch_lines
    ]

    with Path(target_path_str).open(mode='r+b', buffering=0) as target_file:
        return apply_patches(target_file, patches, try_both)


def main():
    parser = argparse.ArgumentParser()

    direction_limiter = parser.add_mutually_exclusive_group()
    direction_limiter.add_argument(
        '--normal_only',
        dest='try_reverse',
        action='store_false',
    )
    direction_limiter.add_argument(
        '--reverse_only',
        dest='try_normal',
        action='store_false',
    )

    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
    )
    parser.add_argument(
        '--skip_backup',
        dest='backup',
        action='store_false',
    )

    parser.add_argument(
        '--patch',
        '-p',
        required=True,
        nargs='+',
        help='Filename(s) of .1337 patch(es)',
    )
    parser.add_argument(
        '--target',
        '-t',
        required=True,
        nargs='+',
        help='Filename(s) of target file(s).',
    )

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    for zipped in zip(args.patch, args.target):
        patcher(
            *zipped,
            try_normal=args.try_normal,
            try_reverse=args.try_reverse,
            should_backup=args.backup,
        )


if __name__ == '__main__':
    main()
