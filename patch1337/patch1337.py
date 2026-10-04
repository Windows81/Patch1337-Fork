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


def normalise_target_name(n: str):
    return n.strip().lower()


def group_patch_lines(patch_file_path: Path) -> dict[str, list[str]]:
    '''Check validity of patch file.'''
    result = {}
    target_name = None
    with patch_file_path.open() as patch_file:
        for line in patch_file:

            if line.startswith('>'):
                target_name = normalise_target_name(line[1:])
                continue

            elif target_name is None:
                break

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


def maybe_back_up_file(target_path: Path) -> bool:
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


def parse_patch_line(line: str, target: str) -> patch_info:
    '''Parse a line from the patch file.'''

    (rva_str, patch_str) = line.strip().split(':')
    (patch_from_str, patch_to_str) = patch_str.split('->')
    rva_val = int(rva_str, base=16)

    return patch_info(
        loc=rva_to_file_offset(target, rva_val),
        fr=int(patch_from_str, base=16),
        to=int(patch_to_str, base=16),
    )


def apply_patches(target_file: io.FileIO, patches: list[patch_info], try_normal: bool = True, try_reverse: bool = False) -> bool:
    '''Apply patches to the target file.'''

    def apply_patch(loc: int, v: int):
        target_file.seek(loc)
        target_file.write(bytes([v]))
        logger.debug(
            '0x%X has been patched correctly to 0x%02X' %
            (loc, v)
        )

    is_normal_patch = try_normal
    is_reverse_patch = try_reverse
    for patch in patches:
        target_file.seek(patch.loc)

        [unpatched_bit] = target_file.read(1)
        logger.debug(
            'checking 0x%X : 0x%02X -> 0x%02X [now 0x%02X]' %
            (patch.loc, patch.fr, patch.to, unpatched_bit)
        )

        is_normal_patch &= bool(unpatched_bit == patch.fr)
        is_reverse_patch &= bool(unpatched_bit == patch.to)

        if is_normal_patch or is_reverse_patch:
            continue

        logger.error(
            'unable to verify patches; stopped checking at offset 0x%X' % patch.loc
        )
        return False

    match (try_normal, try_reverse), (is_normal_patch, is_reverse_patch):

        # Case for when the patch file is either (1) empty or (2) full of redundant patches (such as AB->AB).
        case (_, _), (True, True):
            return True

        # Case for when only reverse is requested, but only normal is possible.
        case (False, _), (True, False):
            check = input(
                'all bits in the patch were not yet applied; perform a forwards patch? (y/N): ',
            )
            if check.lower() != 'y':
                return False
            for patch in patches:
                apply_patch(patch.loc, patch.to)
            return True

        case (_, _), (True, False):
            for patch in patches:
                apply_patch(patch.loc, patch.to)
            return True

        # Case for when only normal is requested, but only reverse is possible.
        case (_, False), (False, True):
            check = input(
                'all bits in the patch were already applied; perform a reverse patch? (y/N): ',
            )
            if check.lower() != 'y':
                return False

            for patch in patches:
                apply_patch(patch.loc, patch.fr)
            return True

        case (_, _), (False, True):
            for patch in patches:
                apply_patch(patch.loc, patch.fr)
            return True

        # Execution should never go here.
        case _:
            assert False


def apply_patch_lines(target_path: Path, patch_lines: list[str] | None, should_back_up: bool) -> bool:
    target_filename = normalise_target_name(target_path.name)

    if patch_lines is None:
        logger.error(
            'the .1337 patch is not valid for the selected file (%s); skipping' % target_filename
        )
        return False

    if should_back_up and not maybe_back_up_file(target_path):
        return False

    patches = [
        parse_patch_line(line, target_path)
        for line in patch_lines
    ]

    with Path(target_path).open(mode='r+b', buffering=0) as target_file:
        return apply_patches(target_file, patches, try_normal, try_reverse)


def patcher(
    patch_path: Path,
    target_paths: list[Path],
    try_normal: bool = True,
    try_reverse: bool = False,
    should_back_up: bool = True,
    ignore_target_name: bool = False,
) -> bool:
    if try_normal == False and try_reverse == False:
        return True

    if not patch_path.exists():
        logger.error(
            '%s does not exist' % patch_path
        )
        return False

    patch_data = group_patch_lines(patch_path)
    logger.debug(
        '%s is a valid .1337 patch file' % normalise_target_name(patch_path.name)
    )

    if len(patch_data) == 0:
        logger.error('%s is not a valid .1337 patch file' % patch_path.name)
        return False

    if ignore_target_name:
        if len(patch_data) > 1:
            logger.error('unable to ignore target name if more than one are specified in patch file')
            return False
        if len(target_paths) > 1:
            logger.error('unable to ignore target name if more than one target is specified')
            return False
        return apply_patch_lines(
            target_path=target_paths[0],
            patch_lines=next(patch_data.values()),
            should_back_up=should_back_up,
        )

    result = False
    for target_path in target_paths:
        result |= apply_patch_lines(
            target_path=target_path,
            patch_lines=patch_data.get(target_path),
            should_back_up=should_back_up,
        )
    return result
    


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
        '--ignore_target_name',
        action='store_true',
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
        type=Path,
        nargs='+',
        help='filename(s) of .1337 patch(es)',
    )
    parser.add_argument(
        '--target',
        '-t',
        required=True,
        type=Path,
        nargs='+',
        help='filename(s) of target file(s)',
    )

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    for p in args.patch:
        patcher(
            patch_path=p,
            target_paths=args.target,
            try_normal=args.try_normal,
            try_reverse=args.try_reverse,
            should_back_up=args.backup,
            ignore_target_name=args.ignore_target_name,
        )


if __name__ == '__main__':
    main()
