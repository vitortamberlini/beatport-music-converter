import logging
import os
import subprocess
import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Dict, Any

import requests
from bs4 import BeautifulSoup
from mutagen.aiff import AIFF
from mutagen.id3 import (
    TBPM,
    TALB,
    TIT2,
    TPE1,
    TRCK,
    TDRC,
    TCON,
    TKEY,
    TDOR,
    TDRL,
    TPUB,
    APIC
)

SUPPORTED_TYPES = (".wav", ".aiff", ".mp3", ".flac")
logger = logging.getLogger()


def convert_wav_to_mp3(wav_file, mp3_file):
    subprocess.call([str(Path("ffmpeg/bin/ffmpeg.exe").absolute()), '-i', wav_file, mp3_file])


def convert_to_aiff(old_file_path: str, aiff_file_path: str) -> None:
    command = ["ffmpeg", "-hide_banner", "-loglevel", "error", '-i', old_file_path, aiff_file_path]

    process = subprocess.Popen(command)
    process.wait()


def process_wav(wav_file: Path, aiff_file: Path, tags: dict) -> None:
    convert_to_aiff(str(wav_file.absolute()), str(aiff_file.absolute()))
    add_tags(aiff_file, tags)


def process_mp3(mp3_file: Path, aiff_file: Path, tags: dict) -> None:
    convert_to_aiff(str(mp3_file.absolute()), str(aiff_file.absolute()))
    add_tags(aiff_file, tags)


def process_flac(flac_file: Path, aiff_file: Path, tags: dict) -> None:
    convert_to_aiff(str(flac_file.absolute()), str(aiff_file.absolute()))
    add_tags(aiff_file, tags)


def add_tags(aiff_file, tags):
    audio = AIFF(aiff_file)
    audio.add_tags()
    audio.tags['TIT2'] = TIT2(encoding=3, text=tags['Title'])
    audio.tags['TPE1'] = TPE1(encoding=3, text=tags['Artist'])
    audio.tags['TRCK'] = TRCK(encoding=3, text=tags['Track Number'])
    audio.tags['TALB'] = TALB(encoding=3, text=tags['Album'])
    audio.tags['TDRC'] = TDRC(encoding=3, text=tags['Year'])
    audio.tags['TCON'] = TCON(encoding=3, text=tags['Genre'])
    audio.tags['TBPM'] = TBPM(encoding=3, text=tags['BPM'])
    audio.tags['TKEY'] = TKEY(encoding=3, text=tags['Key'])
    audio.tags['TDOR'] = TDOR(encoding=3, text=tags['Original Release Date'])
    audio.tags['TDRL'] = TDRL(encoding=3, text=tags['Original Release Date'])
    audio.tags['TPUB'] = TPUB(encoding=3, text=tags['Publisher'])
    audio.tags['APIC:Cover (front)'] = APIC(
        mime='image/jpeg',
        type=3,
        desc='Cover (front)',
        data=requests.get(tags['Image']).content
    )

    audio.save()


def get_tags_from_beatport(track_id: int, auth_token: str) -> dict[str | Any, str | Any]:
    """
    To get Auth headers, log in on Beatport and look for this request in the network tab:
    https://www.beatport.com/api/auth/session
    """
    headers = {
        'Authorization': f'Bearer {auth_token}',
        "content-type": "application/json",
    }

    response = requests.get(f"https://api.beatport.com/v4/catalog/tracks/{track_id}", headers=headers)

    if response.status_code == 401:
        raise ValueError()

    if response.status_code == 403:
        raise PermissionError()

    if response.status_code == 404:
        raise NotFoundError()

    response_json = response.json()
    logger.debug(f"{track_id} - Getting tags")
    return {
        'File': f"{response_json['name']} ({response_json['mix_name']})",
        'Title': response_json['name'],
        'Artist': ", ".join([artist['name'] for artist in response_json['artists']]),
        'Track Number': str(response_json['number']),
        'Album': response_json['release']['name'],
        'Year': response_json['new_release_date'][:4],
        "Genre": response_json['genre']['name'],
        "BPM": str(response_json['bpm']),
        'Key': f"{response_json['key']['camelot_number']}{response_json['key']['camelot_letter']}",
        'Original Release Date': response_json['new_release_date'],
        'Publisher': response_json['release']['label']['name'],
        "Image": response_json['release']['image']['uri'],
    }


def escape_invalid_characters(filename: str) -> str:
    return ''.join([character for character in filename if character not in "\"|%:/,.\\[]<>*?"])


def rename_aiff(file: Path, aiff_file: Path, tags: dict) -> None:
    file.rename(aiff_file)


class NotFoundError(Exception):
    pass


def convert_and_add_tags(path: Path, token: str) -> None:
    for file in Path('.').iterdir():
        if not file.is_file():
            logger.warning(f"Skipping {file} - Is not a file")
            continue

        if file.suffix not in SUPPORTED_TYPES:
            logger.warning(f"Skipping {file} - Is not a supported type ({file.suffix})")
            continue

        try:
            track_id = int(file.stem)
        except ValueError:
            logger.warning(f"Skipping {file} - Is not a number")
            continue

        try:
            tags = get_tags_from_beatport(track_id, auth_token=token)
        except ValueError:
            logger.error(f"Breaking script - auth is not valid")
            break
        except PermissionError:
            logger.error(f"Skipping {file} - Is not a number")
            continue
        except NotFoundError:
            logger.error(f"Skipping {file} - Invalid Beatport ID")
            continue

        escaped_filename = escape_invalid_characters(tags['File'])
        aiff_file = path / f"{escaped_filename} - {track_id}.aiff"

        if aiff_file.is_file():
            logger.warning(f"Skipping {file} - File already exists ({aiff_file.name})")
            continue

        file_processing_mapper = {
            ".wav": process_wav,
            ".mp3": process_mp3,
            ".flac": process_flac,
            ".aiff": rename_aiff,
        }

        file_processing_mapper[file.suffix](file, aiff_file, tags)


if __name__ == '__main__':
    # Adds CWD to PYTHONPATH
    sys.path.append(os.getcwd())

    parser = ArgumentParser(description="Converts files and add metadata from Beatport API")
    parser.add_argument(
        "--show-log",
        action="store_true",
        help="Enable logging. If not provided, logging will be disabled."
    )
    parser.add_argument(
        "-path",
        type=Path,
        help="The file or directory path to process."
    )
    parser.add_argument(
        "-token",
        type=str,
        help="Beatport API token."
    )

    args = parser.parse_args()
    if args.show_log:
        logger.setLevel(logging.WARNING)

    output_path: Path = args.path
    if not output_path.is_dir():
        print(f"Error: The path '{args.path}' is not a directory.")
        raise SystemExit(1)

    convert_and_add_tags(
        path=args.path,
        token=args.token,
    )
    exit()
