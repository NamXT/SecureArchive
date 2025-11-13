import argparse
import sys
from getpass import getpass
from typing import List

from .engine import (
    encrypt_path,
    decrypt_container,
    list_container as engine_list_container,
    verify_container as engine_verify_container,
    change_password as engine_change_password,
    SecureArchiveError,
    InvalidContainerError,
    WrongPasswordError,
)
from .i18n import tr


def _resolve_lang(lang: str | None) -> str:
    if not lang:
        return "de"
    lang = lang.lower()
    if lang not in ("de", "en"):
        return "en"
    return lang


def _prompt_password(lang: str, confirm: bool = False) -> str:
    pw = getpass(tr(lang, "password.prompt"))
    if confirm:
        pw2 = getpass(tr(lang, "password.prompt_confirm"))
        if pw != pw2:
            print(f"{tr(lang, 'common.error')}: {tr(lang, 'password.mismatch')}", file=sys.stderr)
            sys.exit(1)
    return pw


def _handle_encrypt(args, lang: str):
    from pathlib import Path

    input_path = args.input
    output_path = args.output
    iterations = args.iterations
    force = args.force

    src = Path(input_path)
    if not src.exists():
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'encrypt.source_missing')}", file=sys.stderr)
        sys.exit(1)

    dst = Path(output_path)
    if dst.exists() and not force:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'encrypt.overwrite_blocked')}", file=sys.stderr)
        sys.exit(1)

    print(tr(lang, "encrypt.start"))
    password = _prompt_password(lang, confirm=True)

    try:
        encrypt_path(input_path, output_path, password, iterations=iterations, overwrite=force)
    except SecureArchiveError as ex:
        print(f"{tr(lang, 'common.error')}: {ex}", file=sys.stderr)
        sys.exit(1)
    except OSError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.io')}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.generic')}", file=sys.stderr)
        sys.exit(1)

    print(tr(lang, "encrypt.success"))


def _handle_decrypt(args, lang: str):
    print(tr(lang, "decrypt.start"))
    password = _prompt_password(lang, confirm=False)

    try:
        decrypt_container(args.container, args.output_dir, password)
    except InvalidContainerError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.invalid_container')}", file=sys.stderr)
        sys.exit(1)
    except WrongPasswordError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.wrong_password')}", file=sys.stderr)
        sys.exit(1)
    except OSError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.io')}", file=sys.stderr)
        sys.exit(1)
    except SecureArchiveError as ex:
        print(f"{tr(lang, 'common.error')}: {ex}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.generic')}", file=sys.stderr)
        sys.exit(1)

    print(tr(lang, "decrypt.success"))


def _handle_list(args, lang: str):
    print(tr(lang, "list.start"))
    password = _prompt_password(lang, confirm=False)

    try:
        entries = engine_list_container(args.container, password)
    except InvalidContainerError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.invalid_container')}", file=sys.stderr)
        sys.exit(1)
    except WrongPasswordError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.wrong_password')}", file=sys.stderr)
        sys.exit(1)
    except SecureArchiveError as ex:
        print(f"{tr(lang, 'common.error')}: {ex}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.generic')}", file=sys.stderr)
        sys.exit(1)

    print(tr(lang, "list.header"))
    for e in entries:
        line = tr(lang, "list.entry", path=e["path"], size=e["size"])
        print(f" - {line}")


def _handle_verify(args, lang: str):
    print(tr(lang, "verify.start"))
    password = _prompt_password(lang, confirm=False)

    try:
        ok = engine_verify_container(args.container, password)
    except Exception:
        ok = False

    if ok:
        print(tr(lang, "verify.success"))
        sys.exit(0)
    else:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'verify.failure')}", file=sys.stderr)
        sys.exit(1)


def _handle_passwd(args, lang: str):
    current_pw = getpass(tr(lang, "password.current"))
    new_pw = getpass(tr(lang, "password.new"))
    new_pw_confirm = getpass(tr(lang, "password.new_confirm"))
    if new_pw != new_pw_confirm:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'password.mismatch')}", file=sys.stderr)
        sys.exit(1)

    try:
        engine_change_password(args.container, current_pw, new_pw, iterations=args.iterations)
    except InvalidContainerError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.invalid_container')}", file=sys.stderr)
        sys.exit(1)
    except WrongPasswordError:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.wrong_password')}", file=sys.stderr)
        sys.exit(1)
    except SecureArchiveError as ex:
        print(f"{tr(lang, 'common.error')}: {ex}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print(f"{tr(lang, 'common.error')}: {tr(lang, 'error.generic')}", file=sys.stderr)
        sys.exit(1)

    print(tr(lang, "passwd.success"))


def main(argv: List[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]

    preliminary_parser = argparse.ArgumentParser(add_help=False)
    preliminary_parser.add_argument("--lang", "-l")
    prelim_args, _ = preliminary_parser.parse_known_args(argv)
    lang = _resolve_lang(prelim_args.lang)

    parser = argparse.ArgumentParser(description=tr(lang, "cli.description"))
    parser.add_argument(
        "--lang",
        "-l",
        help=tr(lang, "cli.lang_help"),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help=tr(lang, "cli.cmd.encrypt"),
    )
    encrypt_parser.add_argument(
        "input",
        help=tr(lang, "cli.arg.input"),
    )
    encrypt_parser.add_argument(
        "output",
        help=tr(lang, "cli.arg.output"),
    )
    encrypt_parser.add_argument(
        "--iterations",
        type=int,
        default=300_000,
        help=tr(lang, "cli.arg.iterations"),
    )
    encrypt_parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help=tr(lang, "cli.arg.force"),
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help=tr(lang, "cli.cmd.decrypt"),
    )
    decrypt_parser.add_argument(
        "container",
        help=tr(lang, "cli.arg.container"),
    )
    decrypt_parser.add_argument(
        "output_dir",
        help=tr(lang, "cli.arg.output_dir"),
    )

    list_parser = subparsers.add_parser(
        "list",
        help=tr(lang, "cli.cmd.list"),
    )
    list_parser.add_argument(
        "container",
        help=tr(lang, "cli.arg.container"),
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help=tr(lang, "cli.cmd.verify"),
    )
    verify_parser.add_argument(
        "container",
        help=tr(lang, "cli.arg.container"),
    )

    passwd_parser = subparsers.add_parser(
        "passwd",
        help=tr(lang, "cli.cmd.passwd"),
    )
    passwd_parser.add_argument(
        "container",
        help=tr(lang, "cli.arg.container"),
    )
    passwd_parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help=tr(lang, "cli.arg.iterations"),
    )

    args = parser.parse_args(argv)
    lang = _resolve_lang(args.lang)

    if args.command == "encrypt":
        _handle_encrypt(args, lang)
    elif args.command == "decrypt":
        _handle_decrypt(args, lang)
    elif args.command == "list":
        _handle_list(args, lang)
    elif args.command == "verify":
        _handle_verify(args, lang)
    elif args.command == "passwd":
        _handle_passwd(args, lang)
    else:
        parser.print_help()
        sys.exit(1)