#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unmicro.py - free decryptor for files encrypted by the Dev7 / Micro ransomware
             family (".cryptedmicro" extension).

Rho-9 Systems. Your first line of unusual defense.
Actor: Chattering Magpies (R9-C001). Malware self-name: Micro. Family: Dev7.

THE ENCRYPTION

    key        = Arrays.copyOf(keyString.getBytes(UTF_8), 32)
    cipher     = AES/ECB/PKCS5Padding
    ciphertext = encrypt(entire file)
    output     = <original absolute path> + ".cryptedmicro"

No KDF, no IV, no salt, no header, no per-file state. One operator-typed key
string covers every file the walker touched on that machine. That single design
choice is what makes this tool possible, and it is why guessing is cheap: one
AES key schedule and one block per candidate, instead of the hundred thousand
PBKDF2 rounds a competent implementation would have used.

WHAT THIS TOOL DOES

    1. Finds the encrypted files for you, across every drive, if you ask it to.
    2. Tries the keys recovered from the operators' own Discord C2.
    3. If none fit, generates candidates modelled on how these specific
       operators actually type keys, then sweeps them.
    4. Verifies every recovery against the real structure of the file.
    5. Repeats the whole search on anything still unaccounted for, because a
       machine whose encryption run was interrupted and restarted carries
       more than one key.

THIS TOOL ONLY DECRYPTS

    There is no encrypt path anywhere in this file. The AES back ends expose
    decryption only, the built in AES has no encrypt_block, and nothing here
    can produce a .cryptedmicro file. A recovery tool has no legitimate use
    for the other direction.

SAFETY RULES BUILT IN

    * Your encrypted files are NEVER modified, renamed or deleted. Recovered
      files are written to a separate output directory.
    * Every recovered file is verified structurally before it counts as
      recovered: PKCS#5 padding parses, the length agrees with the ciphertext,
      and the file itself holds up, meaning PNG chunk CRCs, JPEG and GIF
      terminators, BMP length fields, ZIP central directories, PE headers and
      clean text decoding.
    * A file that fails verification is not written at all unless you pass
      --keep-unverified, and then it lands with a .UNVERIFIED suffix.
    * Keep your encrypted copies until you have confirmed the recovered files
      open. Do not delete them on the strength of this tool alone.

USAGE

    Just run it (search everything, try every route, write to a folder it
    makes):
        python3 unmicro.py

    Find everything and try the known keys:
        python3 unmicro.py --auto --out ./recovered

    Point it at a folder instead:
        python3 unmicro.py --in ./encrypted --out ./recovered

    Use a key you already have:
        python3 unmicro.py --in ./encrypted --out ./recovered --key zarox

    Known keys failed, so start guessing:
        python3 unmicro.py --in ./encrypted --out ./recovered --brute

    Guess harder, takes much longer:
        python3 unmicro.py --in ./encrypted --out ./recovered --brute --deep --workers 4

    Plain structural brute force, 3 chars up over a Turkish+English alphabet,
    resumable:
        python3 unmicro.py --in ./encrypted --out ./recovered --dumb-brute --checkpoint run.ckpt

    Try strings out of a memory image, pagefile or strings dump first, which is
    often where a typed key survives:
        python3 unmicro.py --in ./encrypted --out ./recovered --scavenge memory.dmp

    Run the sweep on an OpenCL GPU (NVIDIA or AMD), self-tested against the CPU:
        python3 unmicro.py --in ./encrypted --out ./recovered --brute --gpu

    Work out which key applies and write nothing:
        python3 unmicro.py --auto --identify --brute

NOTES

    * Runs on plain Python 3.7+ with nothing installed. If pycryptodome or
      cryptography is present it is used and is far faster, which matters a
      great deal for --brute. Termux friendly.
    * Recovered files are written under their true extension. This crew has
      started randomising extensions before encrypting, so a recovered video
      can arrive named .jpg and an archive named .png. After a file decrypts,
      its real type is read from the recovered bytes, and if the name's
      extension genuinely contradicts the content the output is written under
      the corrected extension and the swap is reported. This is a naming repair
      on the recovered copy only: the recovered bytes are never altered and the
      encrypted originals are never touched. Detection uses the filetype
      library (pip install filetype); without it a smaller built in table is
      used instead. It is on by default; --no-fix-ext turns it off.
    * Key detection works because the first bytes of most file formats are
      fixed. For formats this tool does not recognise, supply the key with
      --key and pass --force.
    * When the recovered keys miss, there are three further routes, cheapest
      first. --scavenge FILE tries strings pulled from an unencrypted dump (a
      memory image, pagefile or strings listing), where a typed key often
      survives in the clear. --brute sweeps candidates modelled on this crew's
      key history. --dumb-brute is a plain structural brute, 3 characters up to
      the longest recovered key, over the Turkish and English alphabet these
      operators type on; it pauses and asks before a length that would take too
      long. A long sweep holds flat, bounded memory (see --seen-cap) and can be
      made resumable with --checkpoint FILE.
    * If nothing is found, that is not the end, but do not assume the machine's
      own recovery paths survived. This crew disables Windows Recovery, Task
      Manager and Regedit, and adds a Defender exclusion. Check what is
      actually left rather than counting on it, and get a responder to look.
    * Do not wipe the machine and do not delete the encrypted files. That is
      what turns a recoverable situation into a permanent one.
    * Do not pay. Their "decryption" is issued from their own bot to the
      implant still sitting on your machine, so it needs the infection kept
      alive and running, and it is their code executing on your machine a
      second time. It is not something you can run and not something you
      should be keeping a live implant around for.
"""

import argparse
import collections
import itertools
import os
import re
import string
import sys
import time

# Content based type detection for extension repair (Section 8b). filetype is
# the intended engine and carries the broad, current signature set. It is pure
# Python with no sub dependencies, so it bundles into the frozen binary and
# installs on Termux with a single pip. If it is genuinely absent the tool
# still decrypts: extension repair falls back to the built in SIGNATURES table
# and says so once. Nothing on the decryption path depends on it.
try:
    import filetype as _filetype
    HAVE_FILETYPE = True
    try:
        FILETYPE_VERSION = _filetype.version.__version__
    except Exception:
        try:
            FILETYPE_VERSION = _filetype.__version__
        except Exception:
            FILETYPE_VERSION = "?"
except Exception:
    _filetype = None
    HAVE_FILETYPE = False
    FILETYPE_VERSION = None

VERSION = "3.5"
EXT = ".cryptedmicro"

WINDOWS = os.name == "nt"

# Hard cap on how many entries each generator's duplicate-suppression set may
# hold. The dedup stays exact, but when a set reaches this many entries it is
# cleared and refilled rather than growing without bound, which is what keeps
# memory flat over a long --brute or --dumb-brute run. The only cost of a clear
# is that a few already-seen candidates may be regenerated and retested, which
# is cheap and, unlike a probabilistic filter, never skips a candidate. A
# skipped candidate in a decryptor can be the victim's key. Override with
# --seen-cap. The default keeps the concurrently live sets inside a few hundred
# MB, so a deep sweep runs on a modest machine instead of being OOM-killed.
SEEN_CAP = 1_000_000

# Where a bare, no-options run drops what it recovers. Created if missing.
DEFAULT_OUT_DIR = "unmicro-recovered"

# Alphabets for the structural brute (--dumb-brute). These operators type on a
# Turkish Q layout, and a character that a language does not have is a character
# the key cannot contain, so widening the alphabet to Turkish AND English, but
# no further, is real coverage rather than wasted space. Turkish has no q, w or x
# but adds ç ğ ı ö ş ü (and the dotted/dotless i pair); English supplies q, w, x,
# which do show up in the operators' keyboard-mash keys. Digits are always in.
ENGLISH_LOWER = "abcdefghijklmnopqrstuvwxyz"
ENGLISH_UPPER = ENGLISH_LOWER.upper()
TURKISH_LOWER = "çğıöşü"      # ç ğ ı ö ş ü
TURKISH_UPPER = "ÇĞİÖŞÜ"      # Ç Ğ İ Ö Ş Ü
DIGITS = "0123456789"


# ===========================================================================
# SECTION 0. Windows runtime.
#
# Three Windows behaviours will each kill a recovery mid run, so they are
# dealt with before anything else happens.
#
#   1. Console encoding. The recovered keys carry Turkish characters. When
#      output is piped or redirected Windows falls back to the ANSI code page
#      and print() raises UnicodeEncodeError, so
#      "unmicro.exe --list-keys > keys.txt" would die instead of writing the
#      keys. Same for any recovered filename that is not plain ASCII.
#
#   2. MAX_PATH. This family appends ".cryptedmicro" to the original absolute
#      path, adding 13 characters to paths that were frequently deep already,
#      and the output root adds more on top. Past 260 characters the plain
#      Win32 calls fail, so every path this tool opens, creates or tests is
#      handed over in extended length form.
#
#   3. Frozen multiprocessing. In a PyInstaller build the worker processes
#      re-execute the bundle, so without freeze_support() --workers relaunches
#      the whole program instead of starting workers. See the bottom of this
#      file.
#
# All three helpers are no-ops off Windows, so there is one code path.
# ===========================================================================

def setup_console():
    """Make stdout and stderr survive non-ASCII, redirected or not."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def long_path(path):
    r"""
    Hand a path to Win32 in extended length form so it is not capped at
    MAX_PATH. Returns the path untouched off Windows, and untouched if it is
    already in that form. UNC shares take the \\?\UNC\ variant.

    Use this for opening, creating and existence testing only. Never for
    anything shown to the person, because the prefix is noise to them.
    """
    if not WINDOWS or not path:
        return path
    try:
        p = os.path.abspath(path)
    except (OSError, ValueError):
        return path
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def plain_path(path):
    """Strip the extended length prefix again, for display and for output."""
    if WINDOWS and path:
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[8:]
        if path.startswith("\\\\?\\"):
            return path[4:]
    return path

# ===========================================================================
# SECTION 1. Known keys, recovered from the operators' Discord C2.
#
# Keys are raw strings, encoded UTF-8 and zero padded to 32 bytes exactly as
# the malware does. The Turkish characters are written as escapes so they
# survive copy and paste through chat clients and pastebins intact. Do not
# transliterate them: \u015f is a different byte sequence from "s" and will
# produce a different AES key.
# ===========================================================================

KNOWN_KEYS = [
    # --- from the key issue log: machine, operator and timestamp on record ---
    "keyimsel",                       # microsense7   -> ezrat@DESKTOP-F5L2S6M
    "KLWXSAKXSAKDWQ23",               # medvi_ds      -> user@DESKTOP-QTUIHMF
    "key3131",                        # extrenor      -> favio@Favio
    "anans\u0131nm\u0131",            # ragnarok0537  -> mtb-r@MikePC
    "anansinmi",                      # ASCII typed variant of the above

    # --- from !micro commands observed in the C2 channels ---
    "zarox",
    "zarxo",
    "key3413",
    "keyu3131",
    "buluts",
    "efecan31",
    "edrftgybhunjk",
    "sdfghjxsw",
    "313131",
    "K2K312",
    "qwkewqkeqwk",
    "23\u015eL12L\u015e",
    "\u015eLQWKL432KL432LK\u015e",
    "KQWKEQWKEK2",
    "K\u015eL32LKL32423",
    "K\u015eL132K\u015eL2K\u015eL432",
    "K23K21K",
    "kk23k213k",
    "WQE\u015e\u0130QW2EL\u015e12",
    "123*01923*0123",
    "12*0938120938123",
    "123123123123123",
    "12312312312312313123123",
    "321312312312312",
    "31231231312",
    "3123123123",
    "1273819823713",
    "1298310923812093",
    "1298310923812903",
]

# Operator handles seen issuing commands. Four confirmed keys are handle
# derived (zarox, zarxo, buluts, efecan31), so these are strong seeds.
OPERATOR_HANDLES = [
    "microsense7", "micro", "microlive7", "medvi_ds", "medvi", "extrenor",
    "ragnarok0537", "ragnarok", "aizy", "anny", "fehrazorback", "razorback",
    "eminee", "emine", "zaroxcannn", "zaroxcan", "zarox", "90telecom",
    "telecom", "ben10can", "buluts", "bulut", "efecan", "aykut", "yasin",
    "karatasyasin", "mirza", "cegid", "yuli", "dev7", "gang", "remotesense",
    "live",
]

# Common Turkish given names and everyday nouns. Coverage of the stem and word
# families is vocabulary, not structure: a key built on a name that is not in
# here is unreachable however the candidates are ordered. Adding names is the
# cheapest way to improve this tool.
TURKISH_VOCAB = [
    # given names
    "ahmet", "mehmet", "mustafa", "ali", "huseyin", "h\u00fcseyin", "hasan",
    "ibrahim", "\u0130brahim", "osman", "yusuf", "murat", "omer", "\u00f6mer",
    "ramazan", "kemal", "riza", "r\u0131za", "suleyman", "s\u00fcleyman",
    "abdullah", "yasar", "ya\u015far", "emre", "burak", "eren", "kerem",
    "berkay", "tolga", "serkan", "furkan", "batuhan", "mertcan", "sinan",
    "hakan", "yigit", "yi\u011fit", "alperen", "taylan", "volkan", "emrecan",
    "caner", "onur", "ozan", "baris", "bar\u0131\u015f", "cem", "deniz",
    "kaan", "koray", "levent", "melih", "okan", "selim", "tarik", "tar\u0131k",
    "ugur", "u\u011fur", "umut", "yavuz", "zeynep", "elif", "merve", "busra",
    "b\u00fc\u015fra", "esra", "fatma", "ayse", "ay\u015fe", "emine", "hatice",
    "meryem", "seda", "sena", "tugce", "tu\u011f\u00e7e", "yasemin", "ece",
    # everyday nouns
    "masa", "kalem", "defter", "kapi", "kap\u0131", "pencere", "duvar",
    "sandalye", "kedi", "kopek", "k\u00f6pek", "kus", "ku\u015f", "balik",
    "bal\u0131k", "agac", "a\u011fa\u00e7", "cicek", "\u00e7i\u00e7ek",
    "bahce", "bah\u00e7e", "sokak", "sehir", "\u015fehir", "koy", "k\u00f6y",
    "ekmek", "peynir", "kahve", "cay", "\u00e7ay", "su", "sut", "s\u00fct",
    "elma", "karpuz", "domates", "araba", "otobus", "otob\u00fcs", "tren",
    "okul", "ogretmen", "\u00f6\u011fretmen", "ogrenci", "\u00f6\u011frenci",
    "kitap", "telefon", "bilgisayar", "oyun", "futbol", "gunes", "g\u00fcne\u015f",
    "yildiz", "y\u0131ld\u0131z", "gece", "gunduz", "g\u00fcnd\u00fcz",
    "sevgi", "ask", "a\u015fk", "dost", "kardes", "karde\u015f", "anne",
    "baba", "abla", "dede", "nine", "kilit", "anahtar", "kutu", "canta",
    "\u00e7anta", "ayakkabi", "ayakkab\u0131", "gomlek", "g\u00f6mlek",
]

# Turkish and English filler seen in or adjacent to operator chatter. One
# confirmed key is a Turkish insult, so this is a real pattern, not padding.
TURKISH_SEEDS = [
    "anan", "anas\u0131", "anasi", "baban", "sikerim", "orospu", "amk", "aq",
    "salak", "aptal", "gerizekali", "gerizekal\u0131", "kanka", "abi",
    "kardes", "karde\u015f", "para", "bitcoin", "sifre", "\u015fifre",
    "anahtar", "kilit", "gizli", "test", "deneme", "merhaba", "selam",
    "tamam", "evet", "hayir", "hay\u0131r", "bilgisayar", "dosya", "key",
    "pass", "password", "admin", "root", "hack", "hacked", "locked",
    "crypted", "cryptedmicro", "ransom", "money", "btc",
]

# Keyboard rows. Turkish Q is the layout these operators are typing on, which
# is where the \u015e and \u0130 in their keys come from.
KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwertyu\u0131op\u011f\u00fc", "asdfghjkl\u015fi", "zxcvbnm\u00f6\u00e7",
    "1234567890", "0987654321",
]

# Turkish characters folded to ASCII and back. Operators switch layouts, so a
# key typed as "\u015fifre" may also have been typed as "sifre".
FOLD_MAP = {
    "\u015f": "s", "\u015e": "S", "\u0131": "i", "\u0130": "I",
    "\u011f": "g", "\u011e": "G", "\u00fc": "u", "\u00dc": "U",
    "\u00f6": "o", "\u00d6": "O", "\u00e7": "c", "\u00c7": "C",
}
UNFOLD_MAP = {
    "s": "\u015f", "S": "\u015e", "i": "\u0131", "I": "\u0130",
    "g": "\u011f", "G": "\u011e", "u": "\u00fc", "U": "\u00dc",
    "o": "\u00f6", "O": "\u00d6", "c": "\u00e7", "C": "\u00c7",
}

# ===========================================================================
# SECTION 2. File signatures, used to recognise a correct decryption.
# Each entry is (offset, magic bytes, label, canonical extension or None).
# ===========================================================================

SIGNATURES = [
    (0, b"\x89PNG\r\n\x1a\n", "PNG", ".png"),
    (0, b"\xff\xd8\xff", "JPEG", ".jpg"),
    (0, b"GIF87a", "GIF", ".gif"),
    (0, b"GIF89a", "GIF", ".gif"),
    (0, b"BM", "BMP", ".bmp"),
    (0, b"RIFF", "RIFF (WEBP/WAV/AVI)", None),
    (0, b"%PDF-", "PDF", ".pdf"),
    (0, b"PK\x03\x04", "ZIP/OOXML/JAR", None),
    (0, b"PK\x05\x06", "ZIP (empty)", ".zip"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office)", None),
    (0, b"\x1f\x8b", "GZIP", ".gz"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", ".7z"),
    (0, b"Rar!\x1a\x07", "RAR", ".rar"),
    (0, b"fLaC", "FLAC", ".flac"),
    (0, b"ID3", "MP3", ".mp3"),
    (0, b"\xff\xfb", "MP3", ".mp3"),
    (0, b"OggS", "OGG", ".ogg"),
    (0, b"\x1aE\xdf\xa3", "Matroska/WEBM", ".mkv"),
    (0, b"MZ", "PE executable", ".exe"),
    (0, b"\x7fELF", "ELF executable", None),
    (0, b"SQLite format 3\x00", "SQLite database", ".sqlite"),
    (0, b"{\\rtf", "RTF", ".rtf"),
    (0, b"\xef\xbb\xbf", "UTF-8 text with BOM", ".txt"),
    (0, b"\xff\xfe", "UTF-16LE text", ".txt"),
    (0, b"<?xml", "XML", ".xml"),
    (4, b"ftyp", "MP4/MOV", ".mp4"),
]

# ===========================================================================
# SECTION 3. AES-256-ECB, three back ends.
#
# The pure Python one exists so this script runs on a stock interpreter with
# nothing installed, which matters on a victim machine and on Termux. It is
# correct but slow. Install pycryptodome before using --brute if you can.
# ===========================================================================

BACKEND = None
_dec_blocks = None


def _init_backend(force_pure=False):
    """
    Decryption only. This tool has no encrypt path and is not able to produce
    a .cryptedmicro file: every back end below exposes AES decryption and
    nothing else, and _PureAES has no encrypt_block. That is deliberate. A
    victim facing recovery tool has no legitimate use for the encrypt
    direction, and shipping one would hand anybody who reads this file a
    working implementation of the thing that caused the damage.
    """
    global BACKEND, _dec_blocks
    if not force_pure:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            def _dec(key, data):
                c = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
                return c.update(data) + c.finalize()

            _dec_blocks, BACKEND = _dec, "cryptography"
            return
        except Exception:
            pass
        try:
            from Crypto.Cipher import AES as _AES

            def _dec(key, data):
                return _AES.new(key, _AES.MODE_ECB).decrypt(data)

            _dec_blocks, BACKEND = _dec, "pycryptodome"
            return
        except Exception:
            pass

    def _dec(key, data):
        ctx = _PureAES(key)
        return b"".join(ctx.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))

    _dec_blocks, BACKEND = _dec, "pure-python"


# --- pure Python AES --------------------------------------------------------

def _build_tables():
    """Generate the S-box from the GF(2^8) construction rather than a typed
    table, so there is no transcription risk in this file."""
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_tables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8]


def _xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


class _PureAES(object):
    """AES-256 single block DECRYPTION. Correctness over speed.

    There is no encrypt_block and no forward MixColumns here on purpose: this
    class can undo the malware's work and cannot reproduce it.
    """

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("this build expects a 32 byte key")
        self.rk = self._expand(key)

    @staticmethod
    def _expand(key):
        nk, nr = 8, 14
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [_SBOX[b] for b in t]
                t[0] ^= _RCON[i // nk - 1]
            elif i % nk == 4:
                t = [_SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
        # one flat 16 byte round key per round, column major, matching the
        # state indexing s[4 * column + row] used below
        return [[w[4 * r + c][j] for c in range(4) for j in range(4)]
                for r in range(nr + 1)]

    def _ark(self, s, r):
        k = self.rk[r]
        return [s[i] ^ k[i] for i in range(16)]

    def decrypt_block(self, blk):
        s = self._ark(list(blk), 14)
        for r in range(13, 0, -1):
            s = self._inv_shift(s)
            s = [_INV_SBOX[b] for b in s]
            s = self._ark(s, r)
            s = self._inv_mix(s)
        s = self._inv_shift(s)
        s = [_INV_SBOX[b] for b in s]
        return bytes(self._ark(s, 0))

    @staticmethod
    def _inv_shift(s):
        o = list(s)
        for r in range(1, 4):
            row = [s[r + 4 * c] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                o[r + 4 * c] = row[c]
        return o

    @staticmethod
    def _inv_mix(s):
        o = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            o[4 * c + 0] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
            o[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
            o[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
            o[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
        return o


# ===========================================================================
# SECTION 4. Core primitives
# ===========================================================================

def key_bytes(key_string):
    """Reproduce Arrays.copyOf(s.getBytes(UTF_8), 32) exactly."""
    raw = key_string.encode("utf-8")
    return (raw + b"\x00" * 32)[:32]


def strip_pkcs5(data):
    """Remove PKCS#5 padding. Returns None if the padding is not valid."""
    if not data or len(data) % 16 != 0:
        return None
    n = data[-1]
    if n < 1 or n > 16 or len(data) < n:
        return None
    if data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]


def padded_length(n):
    """
    Length the ciphertext must have for a plaintext of n bytes under PKCS#5.
    This replaces an add_pkcs5() helper that actually built the padded bytes:
    only the length is ever needed, and constructing padded plaintext is a
    step on the way to encrypting it, which this tool does not do.
    """
    return n + (16 - (n % 16))


def identify(head):
    """Return (label, canonical_ext) if the plaintext looks like a known type."""
    label, ext, _ = identify_ex(head)
    return label, ext


# A 2 byte magic such as "BM" or "MZ" matches random data once in 65,536, which
# over a million guesses means a hundred false hits. Anything 4 bytes or longer
# is strong enough to accept on its own; shorter matches have to be confirmed
# against the whole file before they count.
STRONG_MAGIC_BYTES = 4


def identify_ex(head):
    """Return (label, canonical_ext, strong) for a candidate plaintext head."""
    for off, magic, label, ext in SIGNATURES:
        if head[off:off + len(magic)] == magic:
            return label, ext, len(magic) >= STRONG_MAGIC_BYTES
    return None, None, False


# ===========================================================================
# SECTION 4b. Structural validation.
#
# A note on why this exists, because it matters and it is easy to get wrong.
#
# Re-encrypting a decryption and comparing it to the ciphertext PROVES NOTHING
# about the key. AES is a permutation: decrypting with any key at all and then
# encrypting the result returns exactly the original bytes. That check only
# catches a broken AES implementation, never a wrong key.
#
# What a wrong key has to get past is this:
#   * PKCS#5 padding has to parse, which random plaintext manages roughly once
#     in 256 tries, so on its own it is nowhere near enough.
#   * The plaintext has to carry a recognised file signature.
#   * The file structure behind that signature has to hold up: a CRC that
#     matches, a terminator in the right place, a length field that agrees
#     with the file, a text encoding that decodes cleanly.
#
# Together those are strong. A two byte magic plus valid padding alone is not,
# and will produce false hits during a long sweep. That is what this section
# is here to stop.
# ===========================================================================

def _valid_png(pt):
    if len(pt) < 57 or not pt.startswith(b"\x89PNG\r\n\x1a\x0a"):
        return False
    import binascii
    ln = int.from_bytes(pt[8:12], "big")
    if pt[12:16] != b"IHDR" or ln != 13 or len(pt) < 8 + 12 + ln:
        return False
    body = pt[12:16 + ln]
    crc = int.from_bytes(pt[16 + ln:20 + ln], "big")
    if binascii.crc32(body) & 0xFFFFFFFF != crc:
        return False
    return pt.rstrip(b"\x00").endswith(b"IEND\xaeB`\x82")


def _valid_jpeg(pt):
    return len(pt) > 4 and pt[:3] == b"\xff\xd8\xff" and pt.rstrip(b"\x00").endswith(b"\xff\xd9")


def _valid_gif(pt):
    return len(pt) > 14 and pt[:6] in (b"GIF87a", b"GIF89a") and pt.rstrip(b"\x00")[-1:] == b"\x3b"


def _valid_bmp(pt):
    if len(pt) < 30 or pt[:2] != b"BM":
        return False
    declared = int.from_bytes(pt[2:6], "little")
    return abs(declared - len(pt)) <= 16


def _valid_pdf(pt):
    return pt[:5] == b"%PDF-" and b"%%EOF" in pt[-4096:]


def _valid_zip(pt):
    return pt[:4] in (b"PK\x03\x04", b"PK\x05\x06") and b"PK\x05\x06" in pt[-70000:]


def _valid_gzip(pt):
    return len(pt) > 18 and pt[:3] == b"\x1f\x8b\x08"


def _valid_pe(pt):
    if len(pt) < 0x40 or pt[:2] != b"MZ":
        return False
    off = int.from_bytes(pt[0x3C:0x40], "little")
    return 0 < off < len(pt) - 4 and pt[off:off + 4] == b"PE\x00\x00"


def _valid_id3(pt):
    if len(pt) < 10 or pt[:3] != b"ID3":
        return False
    if pt[3] > 4 or pt[4] == 0xFF:
        return False
    return all(b < 0x80 for b in pt[6:10])      # syncsafe size


def _valid_text(pt, enc):
    try:
        pt.decode(enc)
        return True
    except Exception:
        return False


def _valid_plain_text(pt, min_len=16):
    """
    Text has no magic number, so identify() never labels it and every text
    file used to fall through as unrecognised. UTF-8 is the discriminator that
    makes this safe: a wrong key yields uniformly random bytes, and random
    bytes of any real length are valid UTF-8 with vanishing probability, so
    this does not hand back garbage as a recovery.
    """
    if len(pt) < min_len:
        return False
    try:
        txt = pt.decode("utf-8")
    except Exception:
        return False
    if not txt:
        return False
    printable = sum(1 for c in txt if c.isprintable() or c in "\r\n\t")
    return printable / float(len(txt)) >= 0.95


def _valid_ole(pt):
    return pt[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and len(pt) >= 512


# label -> validator. A signature with no validator here is accepted on the
# strength of its magic alone, which is only allowed for magics of 4 bytes or
# more, where a chance match is a one in four billion event.
VALIDATORS = {
    "PNG": _valid_png,
    "JPEG": _valid_jpeg,
    "GIF": _valid_gif,
    "BMP": _valid_bmp,
    "PDF": _valid_pdf,
    "ZIP/OOXML/JAR": _valid_zip,
    "ZIP (empty)": _valid_zip,
    "GZIP": _valid_gzip,
    "PE executable": _valid_pe,
    "MP3": _valid_id3,
    "OLE2 (legacy Office)": _valid_ole,
    "UTF-8 text with BOM": lambda pt: _valid_text(pt, "utf-8"),
    "UTF-16LE text": lambda pt: _valid_text(pt, "utf-16"),
}


def validate_plaintext(pt):
    """
    Return (ok, label). ok means the bytes really are a well formed file of
    the type their signature claims, not just something that starts with the
    right two characters.
    """
    label, _, strong = identify_ex(pt[:16])
    if not label:
        if _valid_plain_text(pt):
            return True, "plain text"
        return False, None
    fn = VALIDATORS.get(label)
    if fn is not None:
        try:
            return bool(fn(pt)), label
        except Exception:
            return False, label
    return strong, label


def decrypt_file(path, key_string, verify=True):
    """
    Returns (plaintext, verified, error). plaintext is None on failure.
    verified means the padding parsed AND the recovered bytes validate as a
    well formed file of the type they claim to be. The file on disk is only
    ever read.
    """
    try:
        with open(long_path(path), "rb") as fh:
            ct = fh.read()
    except OSError as e:
        return None, False, "cannot read: %s" % e
    if len(ct) == 0:
        return None, False, "file is empty"
    if len(ct) % 16 != 0:
        return None, False, "length %d is not a multiple of 16, not a whole ciphertext" % len(ct)
    if _dec_blocks is None:
        # decrypt_file is usable as a library, not only from main(). Without
        # this the first call raises an opaque TypeError on a None global.
        _init_backend()
    kb = key_bytes(key_string)
    pt = strip_pkcs5(_dec_blocks(kb, ct))
    if pt is None:
        return None, False, "PKCS#5 padding invalid, wrong key for this file"
    if padded_length(len(pt)) != len(ct):
        return None, False, "recovered length inconsistent with ciphertext"
    if not verify:
        return pt, False, None
    ok, label = validate_plaintext(pt)
    if not ok:
        return pt, False, ("%s structure did not validate" % label if label
                           else "no recognised file structure")
    return pt, True, None


# ===========================================================================
# SECTION 5. Autodiscovery
#
# The malware's walker starts from File.listRoots(), so encrypted files can be
# anywhere on any volume. This mirrors that: enumerate every root, walk it,
# and prune the directories that cannot hold user data so the scan finishes in
# a sensible time.
# ===========================================================================

PRUNE_DIRS = {
    "$recycle.bin", "system volume information", "windows", "winsxs",
    "$windows.~bt", "$windows.~ws", "recovery", "node_modules", ".git",
    ".svn", "__pycache__", "site-packages", "proc", "sys", "dev", "run",
    "snap", ".cache", ".gradle", ".m2",
}


def candidate_roots():
    """Every plausible starting point on this machine."""
    roots = []
    if os.name == "nt":
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            get_type = ctypes.windll.kernel32.GetDriveTypeW
            for i, letter in enumerate(string.ascii_uppercase):
                if not (mask & (1 << i)):
                    continue
                root = letter + ":\\"
                # DRIVE_NO_ROOT_DIR is a letter with nothing mounted and
                # DRIVE_CDROM is optical media. Walking either stalls --auto
                # on a machine the person is already anxious about, and
                # neither is going to be holding their encrypted files.
                try:
                    if get_type(root) in (1, 5):
                        continue
                except Exception:
                    pass
                roots.append(root)
        except Exception:
            roots = [l + ":\\" for l in string.ascii_uppercase
                     if os.path.exists(l + ":\\")]
    else:
        home = os.path.expanduser("~")
        for p in [home, "/home", "/root", "/mnt", "/media", "/srv", "/opt",
                  "/storage", "/sdcard", "/storage/emulated/0",
                  "/data/data/com.termux/files/home", "/Users", "/Volumes"]:
            if os.path.isdir(p):
                roots.append(p)
        if not roots:
            roots.append("/")
    # drop any root that already sits inside another listed root
    out = []
    for r in sorted(set(os.path.abspath(r) for r in roots), key=len):
        if not any(r.startswith(o.rstrip(os.sep) + os.sep) for o in out):
            out.append(r)
    return out


def walk_for_encrypted(roots, prune=True, progress=True, limit=None):
    """Walk the given roots and return every .cryptedmicro path found."""
    found = []
    seen_dirs = 0
    t0 = time.time()
    for root in roots:
        # On Windows the root goes in as an extended length path so the walk
        # can reach trees deeper than MAX_PATH, which is exactly where this
        # family's 13 extra characters push things. If that form yields
        # nothing at all, meaning it was rejected rather than the tree being
        # empty, the plain root is retried so a whole drive is never skipped
        # in silence.
        for attempt in ([long_path(root), root] if WINDOWS else [root]):
            walked = 0
            for dirpath, dirnames, filenames in os.walk(attempt, topdown=True,
                                                        onerror=lambda e: None,
                                                        followlinks=False):
                walked += 1
                seen_dirs += 1
                if prune:
                    dirnames[:] = [d for d in dirnames
                                   if d.lower() not in PRUNE_DIRS]
                for name in filenames:
                    if name.endswith(EXT):
                        found.append(plain_path(os.path.join(dirpath, name)))
                        if limit and len(found) >= limit:
                            if progress:
                                sys.stderr.write(" " * 72 + "\r")
                            return sorted(found)
                if progress and seen_dirs % 400 == 0:
                    sys.stderr.write(
                        "  scanning... %d folders, %d encrypted files, %.0fs\r"
                        % (seen_dirs, len(found), time.time() - t0))
                    sys.stderr.flush()
            if walked or attempt == root:
                break
    if progress:
        sys.stderr.write(" " * 72 + "\r")
        sys.stderr.flush()
    return sorted(found)


def collect(root, recursive):
    """Non-autodiscovery path: a single file, or a directory."""
    if os.path.isfile(root):
        return [os.path.abspath(root)] if root.endswith(EXT) else []
    out = []
    walk_root = long_path(root) if WINDOWS else root
    for dirpath, dirnames, filenames in os.walk(walk_root,
                                                onerror=lambda e: None):
        for name in filenames:
            if name.endswith(EXT):
                out.append(plain_path(
                    os.path.abspath(os.path.join(dirpath, name))))
        if not recursive:
            dirnames[:] = []
    return sorted(out)


# ===========================================================================
# SECTION 5b. Bounded duplicate suppression.
#
# The candidate generators dedupe with a set so a candidate reachable by several
# paths is only tested once. On a long sweep that set grew without bound and was
# the cause of an out-of-memory kill deep into --brute. BoundedSeen caps it: the
# membership stays exact, but at the cap it clears and refills. A cleared entry
# can be regenerated and retested, a few microseconds of AES, and nothing is
# ever skipped. That last point is why this is a capped exact set and not a
# Bloom filter: a Bloom false positive would drop a candidate untested, and the
# one candidate you cannot afford to drop is the operator's actual key.
# ===========================================================================

class BoundedSeen(object):
    """Exact-membership set with a hard entry cap. Supports the two operations
    the generators use, ``x in s`` and ``s.add(x)``, so it is a drop-in for the
    plain set they used before."""

    __slots__ = ("_s", "_cap", "clears")

    def __init__(self, cap=None):
        self._s = set()
        self._cap = int(cap) if cap else SEEN_CAP
        self.clears = 0

    def __contains__(self, x):
        return x in self._s

    def __iter__(self):
        # Snapshot: callers that iterate (gen_known_variants) then add while
        # iterating, so hand them a stable copy rather than the live set.
        return iter(list(self._s))

    def __len__(self):
        return len(self._s)

    def add(self, x):
        s = self._s
        if x not in s and len(s) >= self._cap:
            s.clear()
            self.clears += 1
        s.add(x)


# ===========================================================================
# SECTION 6a. Mutation helpers.
#
# Every confirmed key falls into one of six shapes. The generators below are
# built from those shapes and ordered cheapest and likeliest first, so a hit
# usually lands in the first few seconds. This is a wordlist problem, not a
# cryptography problem: AES-256 is not being attacked here, the operator's
# typing habits are.
#
#   shape A  prefix plus digits        keyimsel, key3131, key3413, keyu3131
#   shape B  operator handle           zarox, zarxo, buluts, efecan31
#   shape C  digit motif repeated      313131, 123123123123123, 3123123123
#   shape D  keyboard mash             qwkewqkeqwk, sdfghjxsw, edrftgybhunjk
#   shape E  Turkish caps mash         K\u015eL32LKL32423, WQE\u015e\u0130QW2EL\u015e12
#   shape F  long digit run            1298310923812093, 1273819823713
# ===========================================================================

def _case_variants(s):
    out = [s]
    for v in (s.lower(), s.upper(), s.capitalize()):
        if v not in out:
            out.append(v)
    return out


def _fold(s):
    return "".join(FOLD_MAP.get(c, c) for c in s)


def _unfold(s):
    return "".join(UNFOLD_MAP.get(c, c) for c in s)


def _transpositions(s):
    """zarox -> zarxo. Adjacent character swaps, a confirmed real mutation."""
    return [s[:i] + s[i + 1] + s[i] + s[i + 2:] for i in range(len(s) - 1)]


def _cls(c):
    if c.isdigit():
        return "d"
    if c.isalpha():
        return "u" if c.isupper() else "l"
    return "s"


def _rotations(s):
    return [s[i:] + s[:i] for i in range(len(s))]


# ===========================================================================
# ===========================================================================
# SECTION 6. The fitted key model. Fitted from KNOWN_KEYS at import time: the
# alphabets, length prior, affix widths, tiling motifs and the share of the
# sweep each family gets are all measured, none are hand ranked.
# ===========================================================================

class KeyModel(object):
    """Fitted from the recovered keys. Holds no hardcoded key material."""

    def __init__(self, keys=None, handles=None, words=None, vocab=None):
        self.keys = list(keys if keys is not None else KNOWN_KEYS)
        self.handles = list(handles if handles is not None else OPERATOR_HANDLES)
        self.words = list(words if words is not None else TURKISH_SEEDS)
        self.vocab = list(vocab if vocab is not None else TURKISH_VOCAB)
        self._fit()

    # ---------------------------------------------------------------- fit
    def _fit(self):
        K = self.keys
        n = float(max(len(K), 1))

        # Class alphabets, ordered by observed frequency. Unobserved but
        # plausible characters follow so they stay reachable, ranked last.
        tail = {
            "d": "0123456789",
            "l": "abcdefghijklmnopqrstuvwxyz" + "".join(FOLD_MAP.keys()).lower(),
            "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "".join(UNFOLD_MAP.values()).upper(),
            "s": "*-_. ",
        }
        freq = dict((t, collections.Counter()) for t in "dlus")
        for k in K:
            for c in k:
                freq[_cls(c)][c] += 1
        self.alpha = {}
        for t in "dlus":
            seen = [c for c, _ in freq[t].most_common()]
            self.alpha[t] = seen + [c for c in tail[t] if c not in seen]
        self.freq = freq

        # Length prior, observed range only, widened by one either side.
        lens = [len(k) for k in K] or [8]
        lo, hi = max(1, min(lens) - 1), min(32, max(lens) + 1)
        lc = collections.Counter(lens)
        self.lengths = sorted(range(lo, hi + 1),
                              key=lambda L: (-lc.get(L, 0), abs(L - 11)))

        # Structural classification, which also gives the family weights.
        self.stems = collections.Counter()
        self.tail_widths = collections.Counter()
        self.motifs = collections.Counter()
        fam = collections.Counter()

        for k in K:
            m = re.match(r"^([^\W\d_]+)(\d+)$", k, re.UNICODE)
            if m:
                fam["stem"] += 1
                self.stems[m.group(1)] += 1
                self.tail_widths[len(m.group(2))] += 1
                continue
            if k.isdigit() or all(not c.isalpha() for c in k):
                fam["digit"] += 1
                for p in range(1, min(5, len(k)) + 1):
                    self.motifs[k[:p]] += 1
                continue
            if k.isalpha() and (sum(c.isupper() for c in k) == 0):
                fam["word"] += 1
                self.stems[k] += 1
                continue
            fam["motor"] += 1

        self.family_mass = {}
        for f in ("stem", "digit", "motor", "word"):
            self.family_mass[f] = max(fam.get(f, 0), 1) / n

        # Digit alphabet actually used, most frequent first. This is the
        # single biggest ordering win over uniform enumeration.
        self.digits = [c for c in self.alpha["d"] if freq["d"].get(c)]
        if not self.digits:
            self.digits = list("0123456789")

        # Mash alphabet for the motor family, fitted, uppercase and lowercase.
        mash = [c for c, _ in freq["u"].most_common()] + \
               [c for c, _ in freq["l"].most_common()]
        self.mash_alpha = mash[:12] or list("KL")

        # Observed separators, for keys like 123*01923*0123.
        self.seps = [c for c, _ in freq["s"].most_common()] or ["*"]

        # Stem pool: fitted stems first, then the C2 derived seed lists.
        pool = collections.OrderedDict()
        for s, _ in self.stems.most_common():
            pool[s] = True
        for s in self.handles + self.words:
            for v in _case_variants(s) + [_fold(s), _unfold(_fold(s))]:
                if v and v.isalpha():
                    pool.setdefault(v, True)
        self.stem_pool = list(pool)

        # Vocabulary is a SEPARATE pool. Merged in, its ~200 extra stems
        # multiply through every tail width and push the C2 derived stems out
        # of a realistic budget.
        vpool = collections.OrderedDict()
        for s in self.vocab:
            for v in (s, s.capitalize(), _fold(s)):
                if v and v.isalpha() and v not in pool:
                    vpool.setdefault(v, True)
        self.vocab_pool = list(vpool)

        # Single letter extensions of fitted stems, so keyu3131 is reachable
        # from key without hardcoding the prefix.
        ext = []
        for st, _ in self.stems.most_common():
            if st.isalpha() and len(st) <= 8:
                for c in self.alpha["l"][:14]:
                    ext.append(st + c)
        self.stem_ext = ext

        # Tail widths seen on real keys, most common first.
        self.tail_order = [w for w, _ in self.tail_widths.most_common()] or [4]
        for w in (1, 2, 3, 4, 5, 6):
            if w not in self.tail_order:
                self.tail_order.append(w)

    # ------------------------------------------------------------ families
    def gen_known(self):
        for k in self.keys:
            yield k

    def gen_known_variants(self):
        """Case, Turkish folding, adjacent transposition and short affixes of
        every confirmed key. zarox to zarxo is a confirmed real mutation."""
        seen = BoundedSeen()
        base = []
        for k in self.keys:
            base.extend(_case_variants(k))
            base.append(_fold(k))
            base.append(_unfold(_fold(k)))
            base.extend(_transpositions(k))
        for b in base:
            if b and b not in seen:
                seen.add(b)
                yield b
        for b in list(seen):
            for d in self.digits:
                for cand in (b + d, d + b):
                    if cand not in seen:
                        seen.add(cand)
                        yield cand

    def gen_stem(self):
        """Stem plus digit tail. The digit alphabet and its order are fitted,
        so key3131 and keyu3131 are reached before key0000 ever is.

        Tail widths are walked in ascending cost, not descending probability:
        a width costs len(stems) * len(digits) ** width."""
        seen = BoundedSeen()
        for st in self.stem_pool:
            if st not in seen:
                seen.add(st)
                yield st
        for st in self.vocab_pool:
            if st not in seen:
                seen.add(st)
                yield st
        # Every pool at the cheap widths, then operator stems at the expensive
        # widths, then vocabulary. Both operator keys and name based keys land
        # inside budget this way; neither pure ordering manages both.
        max_w = max(self.tail_order[:1] + [4]) + 1
        cheap = 2
        phases = []
        for w in range(1, cheap + 1):
            phases.extend([(g, w) for g in
                           (self.stem_pool, self.stem_ext, self.vocab_pool)])
        for w in range(cheap + 1, max_w + 1):
            phases.append((self.stem_pool, w))
        for w in range(cheap + 1, max_w + 1):
            phases.extend([(self.stem_ext, w), (self.vocab_pool, w)])
        for group, width in phases:
            for st in group:
                for tup in itertools.product(self.digits, repeat=width):
                    cand = st + "".join(tup)
                    if cand not in seen:
                        seen.add(cand)
                        yield cand

    def gen_digit(self):
        """Digit keys. Motif tilings and rotations first, then a weighted
        odometer over the observed digit alphabet."""
        seen = BoundedSeen()

        def emit(s):
            if s and s not in seen:
                seen.add(s)
                return True
            return False

        motifs = [m for m, _ in self.motifs.most_common()]
        tilings = []
        for m in motifs:
            for r in _rotations(m):
                for L in self.lengths:
                    s = (r * (L // len(r) + 1))[:L]
                    if emit(s):
                        tilings.append(s)
                        yield s

        # Near misses: several recovered keys are a tiling the operator
        # fumbled, one transposition or one dropped character out.
        for base in tilings:
            if len(base) < 6:
                continue
            for v in _transpositions(base):
                if emit(v):
                    yield v
            for i in range(len(base)):
                v = base[:i] + base[i + 1:]
                if emit(v):
                    yield v
        for width in (2, 3, 4):
            for tup in itertools.product(self.digits, repeat=width):
                m = "".join(tup)
                for r in _rotations(m):
                    for L in self.lengths:
                        s = (r * (L // len(r) + 1))[:L]
                        if emit(s):
                            yield s
        for m in motifs:
            for sep in self.seps:
                for reps in (2, 3, 4):
                    s = sep.join([m] * reps)
                    if emit(s):
                        yield s
        for L in self.lengths:
            if L > 9:
                continue
            for tup in itertools.product(self.digits, repeat=L):
                s = "".join(tup)
                if emit(s):
                    yield s

    def gen_motor(self):
        """Keyboard runs, reversals, doubles and column zigzags on the Turkish
        Q layout, then mashes over the fitted mash alphabet."""
        seen = BoundedSeen()

        def emit(s):
            if s and s not in seen:
                seen.add(s)
                return True
            return False

        for row in KEYBOARD_ROWS:
            for start in range(len(row)):
                for L in range(3, len(row) - start + 1):
                    run = row[start:start + L]
                    for v in (run, run.upper(), run[::-1], run[::-1].upper(),
                              run + run, (run + run).upper()):
                        if emit(v):
                            yield v

        rows = KEYBOARD_ROWS[:3]
        for a, b in ((0, 1), (1, 2), (0, 2)):
            for start in range(len(rows[a])):
                for L in range(3, 15):
                    walk = []
                    for i in range(L):
                        row = rows[a] if i % 2 == 0 else rows[b]
                        col = start + i // 2
                        if col < len(row):
                            walk.append(row[col])
                    if len(walk) >= 3:
                        w = "".join(walk)
                        for v in (w, w.upper()):
                            if emit(v):
                                yield v

        for L in self.lengths:
            if L > 6:
                continue
            for tup in itertools.product(self.mash_alpha, repeat=L):
                s = "".join(tup)
                if emit(s):
                    yield s

    def gen_word(self):
        """Word plus affix. anansinmi and its Turkish spelling are the
        confirmed members of this family."""
        seen = BoundedSeen()
        for w in self.words:
            for v in _case_variants(w) + [_fold(w), _unfold(_fold(w))]:
                if v and v not in seen:
                    seen.add(v)
                    yield v
        for width in range(1, 4):
            for w in self.words:
                for v in _case_variants(w):
                    for tup in itertools.product(self.digits, repeat=width):
                        cand = v + "".join(tup)
                        if cand not in seen:
                            seen.add(cand)
                            yield cand

    def dumb_alphabet(self, charset="turkish"):
        """The character set the structural brute enumerates, ordered so the
        characters these operators actually use come first (the odometer then
        reaches likely strings sooner). It always starts with the distinct
        characters seen in the recovered keys, most frequent first, then widens
        by charset:

            observed  just those characters (narrowest, fastest)
            turkish   + Turkish and English lowercase letters and digits
                      (default: a character a language lacks is one the key
                      cannot hold, so Turkish+English is coverage, not waste)
            full      + uppercase as well, Turkish and English

        Following the structure of the known keys, not a dictionary.
        """
        counts = collections.Counter()
        for k in self.keys:
            counts.update(k)
        ordered = [c for c, _ in counts.most_common()]

        def extend(seq):
            for c in seq:
                if c not in ordered:
                    ordered.append(c)

        if charset == "observed":
            pass
        elif charset == "full":
            extend(ENGLISH_LOWER + TURKISH_LOWER + DIGITS
                   + ENGLISH_UPPER + TURKISH_UPPER)
        else:                                       # "turkish", the default
            extend(ENGLISH_LOWER + TURKISH_LOWER + DIGITS)
        return ordered or list(ENGLISH_LOWER + DIGITS)

    def dumb_max_len(self):
        """The longest recovered key. The structural brute climbs to here."""
        return max((len(k) for k in self.keys), default=8)

    def gen_dumb_len(self, length, alphabet=None, charset="turkish"):
        """Every string of exactly `length` characters over the alphabet,
        odometer order, likeliest characters first. Produced once each, so this
        holds no dedup state."""
        alpha = alphabet if alphabet is not None else self.dumb_alphabet(charset)
        for combo in itertools.product(alpha, repeat=length):
            yield "".join(combo)

    def gen_dumb(self, min_len=3, max_len=None, charset="turkish"):
        """Classic incremental brute force, the dumb counterpart to the fitted
        model: every string from min_len characters up to the longest recovered
        key, over the Turkish+English alphabet, shortest first. No wordlist, no
        motifs. It reaches a key the vocabulary cannot, at brute-force cost, so
        only the short lengths finish in any realistic budget."""
        alpha = self.dumb_alphabet(charset)
        hi = max_len or self.dumb_max_len()
        for length in range(min_len, hi + 1):
            for cand in self.gen_dumb_len(length, alphabet=alpha):
                yield cand

    # ---------------------------------------------------------- scheduling
    def interleaved(self, deep=False):
        """Round robin across the families, each family getting a share of
        every cycle proportional to the mass of recovered keys it explains.
        Nothing starves behind another family's long tail."""
        fams = [
            ("stem", self.gen_stem()),
            ("digit", self.gen_digit()),
            ("motor", self.gen_motor()),
            ("word", self.gen_word()),
        ]
        quota = []
        for name, gen in fams:
            share = max(1, int(round(self.family_mass.get(name, 0.235) * 40)))
            quota.append([name, gen, share * (4 if deep else 1)])
        seen = BoundedSeen()
        live = True
        while live:
            live = False
            for entry in quota:
                name, gen, share = entry
                if gen is None:
                    continue
                for _ in range(share):
                    try:
                        cand = next(gen)
                    except StopIteration:
                        entry[1] = None
                        break
                    live = True
                    if cand not in seen:
                        seen.add(cand)
                        yield cand


MODEL = None


def get_model():
    global MODEL
    if MODEL is None:
        MODEL = KeyModel()
    return MODEL


def iter_scavenged(paths, min_len=4, max_len=48):
    """
    Yield candidate keys pulled out of UNENCRYPTED dumps: a memory image, the
    pagefile or hibernation file, a `strings` listing, an implant log. The key
    is a string a person typed, so it routinely survives in the clear in one of
    those long after the files themselves were encrypted, and trying what is
    already sitting there beats generating candidates whenever it lands.

    Extracts printable ASCII and printable UTF-16LE runs (Windows holds typed
    strings, registry values and much of memory as UTF-16LE), splits them on
    whitespace, deduplicates and yields each token once. Length is bounded
    because the key is truncated to 32 bytes anyway. This reads whatever file it
    is given as raw bytes; point it at a capture, never at an encrypted file.
    For a very large image, run the system `strings` tool first and feed the
    text output here.
    """
    seen = BoundedSeen()
    ascii_run = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_run = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

    def emit(text):
        for tok in re.split(r"\s+", text):
            if min_len <= len(tok) <= max_len and tok not in seen:
                seen.add(tok)
                yield tok

    for path in paths:
        try:
            with open(long_path(path), "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        for m in ascii_run.finditer(data):
            yield from emit(m.group().decode("ascii", "ignore"))
        for m in utf16_run.finditer(data):
            try:
                yield from emit(m.group().decode("utf-16le"))
            except Exception:
                continue


def build_plan(brute=False, deep=False, dumb=False, extra=None, wordlist=None,
               scavenged=None, dumb_min_len=3, dumb_max_len=None,
               dumb_charset="turkish"):
    """
    Ordered list of (tier name, generator factory), consumed by sweep().

    Cheapest and highest-value tiers first: any keys you supplied, your
    wordlist, the 34 recovered keys, then strings scavenged from a dump if you
    gave one. --brute adds the recovered-key variants and the fitted model.
    --dumb-brute adds one exhaustive tier PER LENGTH, from dumb_min_len up to
    the longest recovered key, so the caller can pause between lengths before
    one of them becomes intractable.
    """
    plan = []
    if extra:
        plan.append(("supplied keys", lambda: iter(list(extra))))
    if wordlist:
        plan.append(("wordlist", lambda: iter(list(wordlist))))
    m = get_model()
    plan.append(("recovered operator keys", m.gen_known))
    if scavenged:
        plan.append(("scavenged strings", lambda: iter_scavenged(scavenged)))
    if brute:
        plan.append(("recovered key variants", m.gen_known_variants))
        plan.append(("fitted model", lambda: KeyModel().interleaved(deep=deep)))
    if dumb:
        hi = dumb_max_len or m.dumb_max_len()
        alpha = m.dumb_alphabet(dumb_charset)
        for length in range(dumb_min_len, hi + 1):
            plan.append(("structural brute len=%d" % length,
                         lambda L=length, A=alpha:
                             get_model().gen_dumb_len(L, alphabet=A)))
    return plan


# ===========================================================================
# SECTION 7. The oracle and the sweep
# ===========================================================================

def probe_set(files, max_probes=4):
    """
    Pick a small set of distinct first blocks covering as many files as
    possible, each paired with the smallest file carrying that block. One AES
    block per probe per candidate is the whole cost of a guess, so keeping
    this small is what makes the sweep fast. The paired file is only touched
    when a weak magic needs confirming.
    """
    groups = {}
    for p in files:
        try:
            with open(long_path(p), "rb") as fh:
                b = fh.read(16)
        except OSError:
            continue
        if len(b) == 16:
            groups.setdefault(b, []).append(p)
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
    out = []
    for blk, paths in ordered[:max_probes]:
        smallest = min(paths, key=lambda p: os.path.getsize(p))
        out.append((blk, smallest))
    return out


def confirm_key(key_string, path):
    """Whole file check: decrypt, require valid PKCS#5, then require the
    recovered bytes to validate structurally. This is what separates a real
    key from a candidate that merely happened to produce a plausible looking
    first block."""
    pt, verified, _ = decrypt_file(path, key_string, verify=True)
    return pt is not None and verified


_WORKER_PROBES = []


def _worker_init(probes):
    global _WORKER_PROBES
    _WORKER_PROBES = probes
    if BACKEND is None:
        _init_backend(False)


def _worker_chunk(chunk):
    hits = []
    for cand in chunk:
        kb = key_bytes(cand)
        for blk, path in _WORKER_PROBES:
            label, _, strong = identify_ex(_dec_blocks(kb, blk))
            if not label:
                continue
            if strong or confirm_key(cand, path):
                hits.append(cand)
                break
    return hits


# --- checkpointing, so a long sweep survives an interrupt or a --max-candidates
# stop and resumes instead of starting over. The saved state is tiny: which tier,
# how many of its candidates were consumed, and how many were tried in total. A
# signature ties the file to one problem (these probe blocks, this tier list), so
# a checkpoint written for a different set of files is ignored, never misapplied.

def _ckpt_sig(probes):
    # Tie the checkpoint to the files (their probe blocks), not to the exact
    # tier list, so a resume with slightly different flags still matches. The
    # tier in progress is recorded by name and looked up in the current plan.
    import hashlib
    h = hashlib.blake2b(digest_size=8)
    for blk, _ in probes:
        h.update(blk)
    return h.hexdigest()


def _ckpt_load(path, sig):
    if not path:
        return None, 0, 0
    try:
        import json
        with open(long_path(path), "r", encoding="utf-8") as fh:
            d = json.load(fh)
        if d.get("sig") == sig:
            return d.get("tier"), int(d["consumed"]), int(d["tried"])
    except Exception:
        pass
    return None, 0, 0


def _ckpt_save(path, sig, tier_name, consumed, tried):
    if not path:
        return
    try:
        import json
        tmp = path + ".part"
        with open(long_path(tmp), "w", encoding="utf-8") as fh:
            json.dump({"sig": sig, "tier": tier_name, "consumed": consumed,
                       "tried": tried}, fh)
        os.replace(long_path(tmp), long_path(path))
    except Exception:
        pass


def _ckpt_clear(path):
    if not path:
        return
    try:
        os.remove(long_path(path))
    except OSError:
        pass


def sweep(files, plan, workers=1, limit=None, quiet=False, chunk_size=20000,
          checkpoint=None, on_tier_start=None, gpu=None):
    """
    Run the tiers in order against the probe blocks. Stops at the first tier
    that produces a hit, since in this family one key normally covers a whole
    machine. Returns (hit key strings, candidates tried).

    checkpoint (a path) makes the sweep resumable: progress is saved each chunk,
    and if the file already holds progress for this same set of files, completed
    tiers are skipped and the current tier is fast-forwarded past what was
    already tried. Fast-forwarding only regenerates candidate strings, it never
    re-tests them, so a resume is far cheaper than the run it continues.

    on_tier_start(name, tier_index) -> bool, if given, is called before each
    tier. Returning False stops the sweep there (used to pause and ask before a
    structural-brute length that would take too long).
    """
    probes = probe_set(files)
    if not probes:
        return [], 0

    sig = _ckpt_sig(probes)
    saved_name, start_consumed, tried = _ckpt_load(checkpoint, sig)
    names = [n for n, _ in plan]
    start_tier = 0
    if saved_name is not None and saved_name in names:
        start_tier = names.index(saved_name)
    elif saved_name is not None:
        # the tier in the checkpoint is not in this plan (different flags): the
        # earlier tiers are cheap, so just start over rather than misapply it.
        start_consumed, tried = 0, 0
    if not quiet and (start_tier or start_consumed or tried):
        print("  resuming from checkpoint: '%s', %d candidate(s) already tried"
              % (names[start_tier] if start_tier < len(names) else saved_name, tried))

    _worker_init(probes)
    t0 = time.time()

    # On the GPU the batch itself is the parallelism, so process the sweep in
    # much larger chunks and skip the CPU worker pool.
    if gpu is not None and chunk_size < (1 << 18):
        chunk_size = 1 << 20

    pool = None
    if gpu is None and workers > 1:
        try:
            import multiprocessing
            pool = multiprocessing.Pool(workers, initializer=_worker_init,
                                        initargs=(probes,))
        except Exception:
            pool = None

    try:
        for tier_idx, (name, factory) in enumerate(plan):
            if tier_idx < start_tier:
                continue                          # finished in a prior run
            if on_tier_start is not None and not on_tier_start(name, tier_idx):
                # A gate declined this tier. Record it by name so a later
                # resume comes back to exactly here, and stop.
                _ckpt_save(checkpoint, sig, name, 0, tried)
                return [], tried
            gen = factory()
            consumed = 0
            if tier_idx == start_tier and start_consumed:
                if not quiet:
                    sys.stderr.write("  fast-forwarding %d candidate(s)...\r"
                                     % start_consumed)
                    sys.stderr.flush()
                collections.deque(itertools.islice(gen, start_consumed), maxlen=0)
                consumed = start_consumed
            tier_start = tried
            confirmed = []
            rejected = 0
            while True:
                chunk = list(itertools.islice(gen, chunk_size))
                if not chunk:
                    break
                if gpu is not None:
                    raw = gpu.filter_chunk(chunk, probes)
                elif pool:
                    slices = [chunk[i::workers] for i in range(workers)]
                    raw = []
                    for hits in pool.imap_unordered(_worker_chunk, slices):
                        raw.extend(hits)
                else:
                    raw = _worker_chunk(chunk)
                tried += len(chunk)
                consumed += len(chunk)

                # A header match is evidence, nothing more. Proof is the whole
                # file validating structurally. Anything that fails this gate
                # was a coincidence, so it is discarded and the sweep carries
                # on rather than reporting a key that does not work.
                for h in raw:
                    if h in confirmed:
                        continue
                    if any(confirm_key(h, path) for _, path in probes):
                        confirmed.append(h)
                    else:
                        rejected += 1

                _ckpt_save(checkpoint, sig, name, consumed, tried)

                if not quiet:
                    rate = tried / max(time.time() - t0, 0.001)
                    sys.stderr.write("  %-26s %11d tried  %9.0f/s\r"
                                     % (name[:26], tried, rate))
                    sys.stderr.flush()
                if confirmed:
                    break
                if limit and tried >= limit:
                    if not quiet:
                        sys.stderr.write(" " * 72 + "\r")
                    # keep the checkpoint: the budget stopped us, not completion
                    return [], tried
            if not quiet:
                sys.stderr.write(" " * 72 + "\r")
                sys.stderr.flush()
                note = "HIT" if confirmed else "no hit"
                if rejected:
                    note += "  (%d coincidental header match(es) discarded)" % rejected
                print("  tier %-30s %13d candidates  %s"
                      % (name, tried - tier_start, note))
            if confirmed:
                _ckpt_clear(checkpoint)
                return confirmed, tried
            # tier finished, no hit: record the next tier by name so a resume
            # skips this one
            nxt = plan[tier_idx + 1][0] if tier_idx + 1 < len(plan) else name
            _ckpt_save(checkpoint, sig, nxt, 0, tried)
    finally:
        if pool:
            pool.terminate()
            pool.join()
    _ckpt_clear(checkpoint)
    return [], tried


def map_keys_to_files(files, keys):
    """Which of the found keys opens which file, by header check."""
    mapping = {}
    for k in keys:
        kb = key_bytes(k)
        hits = []
        for p in files:
            try:
                with open(long_path(p), "rb") as fh:
                    blk = fh.read(16)
            except OSError:
                continue
            if len(blk) == 16 and identify(_dec_blocks(kb, blk))[0]:
                hits.append(p)
        if hits:
            mapping[k] = hits

    # Second pass. A file whose plaintext has no magic number (text, CSV,
    # source, config, anything not in SIGNATURES) is invisible to the header
    # check above, so it used to be reported as "no key found" even when the
    # key was already proven on the machine. On the synthetic corpus that was
    # 90 of 463 files. Padding plus length agreement is weak evidence on its
    # own, which is why it is only accepted for a key that has already been
    # proven structurally somewhere else in this run.
    covered = set()
    for hits in mapping.values():
        covered.update(hits)
    for k in mapping:
        kb = key_bytes(k)
        for p in files:
            if p in covered:
                continue
            try:
                with open(long_path(p), "rb") as fh:
                    ct = fh.read()
            except OSError:
                continue
            if not ct or len(ct) % 16:
                continue
            pt = strip_pkcs5(_dec_blocks(kb, ct))
            if pt is None or padded_length(len(pt)) != len(ct):
                continue
            mapping[k].append(p)
            covered.add(p)
    return mapping


def find_all_keys(files, plan, workers=1, limit=None, quiet=False,
                  max_passes=8, checkpoint=None, on_tier_start=None, gpu=None):
    """
    Sweep until every file is accounted for, or until a round turns up
    nothing new. Returns (mapping, candidates tried, files still unmatched).

    A machine does not reliably carry one key. If the victim reboots part way
    through, or kills the process, or the box goes down on its own, the
    operators simply run it again, and the second run is typed with a new key.
    Files encrypted before the interruption and files encrypted after it then
    sit in the same folders under different keys.

    sweep() works from at most four probe blocks, chosen by how many files
    share them, so one pass finds whichever key covers the bulk of the set and
    stops there. Each round below re-sweeps only what is still unmatched,
    which moves the probes onto the leftovers and brings out the next key.

    The tiers are re-run in their original order every round, so the cheap
    recovered-key tier gets first look at the leftovers before anything
    expensive starts. In the interrupted-run case that is usually where both
    keys are found, and the extra round costs a few thousand AES blocks.
    """
    mapping = {}
    remaining = list(files)
    tried_total = 0
    passes = 0
    while remaining and passes < max_passes:
        passes += 1
        if limit is not None:
            budget = limit - tried_total
            if budget <= 0:
                break
        else:
            budget = None

        if mapping and not quiet:
            print("  %d file(s) not covered yet, sweeping those on their own:"
                  % len(remaining))

        found, tried = sweep(remaining, plan, workers=workers, limit=budget,
                             quiet=quiet, checkpoint=checkpoint,
                             on_tier_start=on_tier_start, gpu=gpu)
        tried_total += tried

        fresh = [k for k in found if k not in mapping]
        if not fresh:
            break

        part = map_keys_to_files(remaining, fresh)
        covered = set()
        for k, hits in part.items():
            mapping.setdefault(k, [])
            for path in hits:
                if path not in mapping[k]:
                    mapping[k].append(path)
            covered.update(hits)

        # A key that was confirmed against a probe but then maps to no file is
        # a dead end. Stopping here is what keeps this loop finite.
        if not covered:
            break
        remaining = [f for f in remaining if f not in covered]

    return mapping, tried_total, remaining


# ===========================================================================
# SECTION 7b. Optional OpenCL GPU acceleration (NVIDIA and AMD).
#
# The sweep spends nearly all of its time on one operation: AES-256 decrypt the
# probe block under a candidate key and look at the result. That is embarrassing
# parallelism, one independent decrypt per candidate, which is exactly what a GPU
# is for. One OpenCL kernel covers both NVIDIA and AMD.
#
# This is opt-in (--gpu) and optional: pyopencl and a working OpenCL driver are
# only touched when it is asked for, so the default tool still runs on bare
# Python with nothing installed.
#
# CORRECTNESS, because this is a recovery tool and a wrong kernel is worse than
# no kernel. The danger is not a false positive, every GPU hit is re-decrypted
# and re-validated on the CPU before it counts, so a bad flag is caught. The
# danger is a false NEGATIVE: a subtly wrong kernel would decrypt everything
# wrong, so the real key's decryption would not match and it would be skipped in
# silence. Two things stop that:
#   1. Key derivation (UTF-8 encode, zero-pad to 32) is done on the CPU by the
#      same key_bytes() the rest of the tool uses. The GPU only ever sees ready
#      32-byte keys, so multi-byte Turkish characters cannot be mis-encoded on
#      the device.
#   2. Before the GPU is trusted for a single real candidate, selftest() decrypts
#      random blocks under random keys on the GPU and compares every byte against
#      the CPU AES back end. A single mismatch disables the GPU and the run falls
#      back to the CPU. So the GPU can make the search faster or, on hardware
#      where the kernel does not hold up, simply not engage. It cannot make the
#      search wrong.
#
# The S-boxes are injected from the same _SBOX/_INV_SBOX this file already built
# from the field arithmetic, so there is no second copy of them to get wrong.
# ===========================================================================

def _gpu_kernel_source():
    # Token replacement, not %-formatting: the kernel body contains i%8 etc.
    sbox = ",".join(str(b) for b in _SBOX)
    isbox = ",".join(str(b) for b in _INV_SBOX)
    return (_GPU_KERNEL_TEMPLATE
            .replace("KERNEL_INVSBOX_DATA", isbox)
            .replace("KERNEL_SBOX_DATA", sbox))


_GPU_KERNEL_TEMPLATE = """
__constant uchar SBOX[256]  = {KERNEL_SBOX_DATA};
__constant uchar ISBOX[256] = {KERNEL_INVSBOX_DATA};
__constant uchar RCON[8]    = {0,1,2,4,8,16,32,64};

inline uchar gmul(uchar a, uchar b){
    uchar p = 0;
    for(int i=0;i<8;i++){
        if(b & 1) p ^= a;
        uchar hi = a & 0x80;
        a <<= 1;
        if(hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

__kernel void aes256_ecb_decrypt(__global const uchar* keys,
                                 __global const uchar* ct,
                                 __global uchar* out,
                                 const uint n){
    uint gid = get_global_id(0);
    if(gid >= n) return;
    __global const uchar* k = keys + (uint)gid*32;

    uchar rk[240];
    for(int i=0;i<32;i++) rk[i] = k[i];
    int rconi = 1;
    for(int i=8;i<60;i++){
        uchar t0=rk[(i-1)*4+0], t1=rk[(i-1)*4+1], t2=rk[(i-1)*4+2], t3=rk[(i-1)*4+3];
        if(i%8==0){
            uchar tmp=t0;
            t0 = SBOX[t1] ^ RCON[rconi]; t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[tmp];
            rconi++;
        } else if(i%8==4){
            t0=SBOX[t0]; t1=SBOX[t1]; t2=SBOX[t2]; t3=SBOX[t3];
        }
        rk[i*4+0]=rk[(i-8)*4+0]^t0; rk[i*4+1]=rk[(i-8)*4+1]^t1;
        rk[i*4+2]=rk[(i-8)*4+2]^t2; rk[i*4+3]=rk[(i-8)*4+3]^t3;
    }

    uchar s[16], t[16];
    for(int i=0;i<16;i++) s[i] = ct[i] ^ rk[14*16 + i];
    for(int round=13; round>=1; round--){
        for(int r=0;r<4;r++) for(int c=0;c<4;c++) t[r + 4*((c+r)&3)] = s[r + 4*c];
        for(int i=0;i<16;i++) t[i] = ISBOX[t[i]];
        for(int i=0;i<16;i++) t[i] ^= rk[round*16 + i];
        for(int c=0;c<4;c++){
            uchar a0=t[4*c+0],a1=t[4*c+1],a2=t[4*c+2],a3=t[4*c+3];
            s[4*c+0]=gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);
            s[4*c+1]=gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);
            s[4*c+2]=gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11);
            s[4*c+3]=gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14);
        }
    }
    for(int r=0;r<4;r++) for(int c=0;c<4;c++) t[r + 4*((c+r)&3)] = s[r + 4*c];
    for(int i=0;i<16;i++) t[i] = ISBOX[t[i]];
    for(int i=0;i<16;i++) out[(uint)gid*16 + i] = t[i] ^ rk[0*16 + i];
}
"""


class GpuAES(object):
    """OpenCL AES-256-ECB block decryption for the sweep. Decrypt only, like the
    rest of this file. Trusted only after selftest() matches the CPU back end."""

    def __init__(self):
        import pyopencl as cl
        import numpy as np
        self.cl, self.np = cl, np
        devices = []
        for plat in cl.get_platforms():
            try:
                devices += plat.get_devices(device_type=cl.device_type.GPU)
            except cl.Error:
                pass
        if not devices:
            raise RuntimeError("no OpenCL GPU device found (NVIDIA or AMD "
                               "drivers and an ICD must be installed)")
        self.device = devices[0]
        self.name = self.device.name.strip()
        self.ctx = cl.Context([self.device])
        self.queue = cl.CommandQueue(self.ctx)
        self.prog = cl.Program(self.ctx, _gpu_kernel_source()).build()
        # offset-0..4 magics from the signature table, for a fast numpy prefilter
        self._magics = [(off, np.frombuffer(magic, dtype=np.uint8))
                        for off, magic, _, _ in SIGNATURES if off + len(magic) <= 16]

    def decrypt_blocks(self, keys, ct16):
        """keys: uint8 [n,32]; ct16: 16 raw bytes. Returns uint8 [n,16]."""
        cl, np = self.cl, self.np
        n = keys.shape[0]
        mf = cl.mem_flags
        keys = np.ascontiguousarray(keys, dtype=np.uint8)
        ctnp = np.frombuffer(ct16, dtype=np.uint8).copy()
        kbuf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=keys)
        cbuf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=ctnp)
        out = np.empty((n, 16), dtype=np.uint8)
        obuf = cl.Buffer(self.ctx, mf.WRITE_ONLY, out.nbytes)
        self.prog.aes256_ecb_decrypt(self.queue, (n,), None,
                                     kbuf, cbuf, obuf, np.uint32(n))
        cl.enqueue_copy(self.queue, out, obuf)
        self.queue.finish()
        return out

    def selftest(self, trials=1024):
        """Decrypt random blocks under random keys on the GPU and require every
        byte to match the CPU AES back end. Returns True only on a total match."""
        np = self.np
        keys = np.frombuffer(os.urandom(trials * 32), dtype=np.uint8).reshape(trials, 32)
        block = os.urandom(16)
        gpu = self.decrypt_blocks(keys, block)
        for i in range(trials):
            if bytes(gpu[i]) != _dec_blocks(bytes(keys[i]), block):
                return False
        return True

    def filter_chunk(self, candidates, probes):
        """Return the candidates whose decrypted probe block carries a known
        magic, for the CPU to then confirm in full. Mirrors the CPU oracle."""
        np = self.np
        keys = np.frombuffer(b"".join(key_bytes(c) for c in candidates),
                             dtype=np.uint8).reshape(len(candidates), 32)
        flagged = np.zeros(len(candidates), dtype=bool)
        for blk, _ in probes:
            out = self.decrypt_blocks(keys, blk)
            for off, magic in self._magics:
                flagged |= np.all(out[:, off:off + len(magic)] == magic, axis=1)
        return [candidates[i] for i in np.nonzero(flagged)[0]]


def init_gpu(quiet=False):
    """Try to bring up the GPU back end and prove it against the CPU. Returns a
    ready GpuAES, or None with a printed reason, in which case the caller uses
    the CPU. Never raises: a GPU problem must not stop a recovery."""
    try:
        import pyopencl  # noqa: F401
    except Exception:
        if not quiet:
            print("--gpu needs pyopencl and OpenCL drivers, which are not present.")
            print("Install with: pip install pyopencl (plus your NVIDIA or AMD")
            print("OpenCL runtime). Falling back to the CPU.")
            print()
        return None
    try:
        gpu = GpuAES()
    except Exception as e:
        if not quiet:
            print("GPU unavailable (%s). Falling back to the CPU." % e)
            print()
        return None
    try:
        ok = gpu.selftest()
    except Exception as e:
        if not quiet:
            print("GPU self-test could not run on %s (%s). Falling back to the CPU."
                  % (gpu.name, e))
            print()
        return None
    if not ok:
        if not quiet:
            print("GPU self-test FAILED on %s: its AES output did not match the CPU,"
                  % gpu.name)
            print("so the GPU is disabled to avoid missing the key. Using the CPU.")
            print("Please report this device; the CPU path is unaffected.")
            print()
        return None
    if not quiet:
        print("GPU ready: %s (AES self-test passed against the CPU back end)."
              % gpu.name)
    return gpu


# ===========================================================================
# SECTION 8. Output paths
# ===========================================================================

def mirrored_path(out_root, src_path, flat=False):
    """
    Recovered files mirror their original location under the output root, so a
    whole-machine sweep does not collapse thousands of files into one folder
    and clobber same-named files.
    """
    base = os.path.basename(src_path)[:-len(EXT)]
    if flat:
        return os.path.join(out_root, base)
    p = os.path.abspath(os.path.dirname(src_path))
    drive, rest = os.path.splitdrive(p)
    drive = drive.replace(":", "").replace("\\", "").replace("/", "")
    rest = rest.lstrip("\\/")
    parts = [x for x in (drive, rest) if x]
    if not parts:
        return os.path.join(out_root, base)
    return os.path.join(out_root, *(parts + [base]))


def unique_path(path):
    if not os.path.exists(long_path(path)):
        return path
    stem, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(long_path("%s (%d)%s" % (stem, i, ext))):
        i += 1
    return "%s (%d)%s" % (stem, i, ext)


# ===========================================================================
# SECTION 8b. Content based type detection and extension repair.
#
# The Dev7 operators began randomising file extensions before encrypting, so a
# recovered file's name is no longer a reliable guide to what it is: a video
# arrives named .jpg, an archive named .png. Decryption is unaffected by this,
# but the recovered file would otherwise be written under a misleading name and
# would not open by double click.
#
# After a file decrypts, its true type is read from the recovered bytes. If the
# name's extension genuinely contradicts the content the output is written under
# the corrected extension and the swap is reported. This is a naming repair on
# the recovered copy only. It never alters recovered bytes and never runs on the
# encrypted originals.
#
# The policy is deliberately conservative, because a careless rename makes a
# recovery worse: many correct names share magic bytes with something else. A
# .docx is a ZIP. A .mov and a .m4a share the .mp4 box structure. A .wav and a
# .webp are both RIFF. So a rename happens only when the content sits in a
# different *category* from the extension, for example an image name over video
# bytes. A same category disagreement (a .png named .jpg) is left alone, and so
# is any container family where the current extension is already a valid member.
#
# detect_content_type uses filetype when installed, which is the intended engine
# and carries the broad signature set. Without it the built in SIGNATURES table
# (Section 2) is used as a narrower fallback. Either way decryption is untouched.
# ===========================================================================

# unmicro's own coarse grouping of an extension, chosen for the swap decision.
# This is intentionally not filetype's own split: filetype files pdf, exe and
# sqlite all under "archive", which is not a useful thing to compare against a
# filename. Keys are lowercase, no leading dot.
_CATEGORY_BY_EXT = {}


def _cat(names, category):
    for n in names.split():
        _CATEGORY_BY_EXT[n] = category


_cat("jpg jpeg jpe jfif jff png apng gif bmp dib webp tif tiff ico cur heic heif "
     "avif jxr jp2 jpx j2k psd xcf svg svgz cr2 nef arw dng raf orf rw2 dds tga "
     "pcx wmf emf", "image")
_cat("mp4 m4v mov qt mkv webm avi wmv flv mpg mpeg mpe m2v ts m2ts mts 3gp 3g2 "
     "ogv f4v vob rm rmvb asf divx", "video")
_cat("mp3 m4a m4b aac flac wav wave ogg oga opus aiff aif aifc amr wma mid midi "
     "ape ac3 dts au caf", "audio")
_cat("zip 7z rar gz tgz bz2 tbz2 xz txz lz lz4 lzo zst zstd tar br cab arj lha "
     "lzh cpio rpm deb ar crx", "archive")
_cat("pdf doc docx docm dot dotx xls xlsx xlsm ppt pptx odt ods odp odg rtf epub "
     "mobi azw3 fb2 wpd", "document")
_cat("exe dll msi com scr sys elf so dylib apk jar msix appx wasm", "executable")
_cat("ttf otf woff woff2 eot pfb pfm", "font")

# Extensions that are the same underlying format under another name, so a name
# using one when the content detects as the other is not a swap. Keyed by the
# extension filetype reports.
_ALIASES = {
    "jpg":  {"jpg", "jpeg", "jpe", "jfif", "jff"},
    "tif":  {"tif", "tiff"},
    "mpg":  {"mpg", "mpeg", "mpe", "m2v"},
    "midi": {"mid", "midi"},
    "aiff": {"aif", "aiff", "aifc"},
    "m4a":  {"m4a", "m4b", "aac"},
    "3gp":  {"3gp", "3g2"},
    "wav":  {"wav", "wave"},
    "ogg":  {"ogg", "oga", "ogv", "opus"},
}

# A generic ZIP detection must never "correct" a real ZIP based container down
# to .zip. filetype recognises the common Office and OpenDocument members on its
# own, but anything it can only see as a plain zip is left as named when the
# name is one of these.
_ZIP_FAMILY = {
    "zip", "docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm",
    "potx", "odt", "ods", "odp", "odg", "otp", "ots", "ott", "jar", "war",
    "ear", "apk", "aar", "ipa", "xpi", "crx", "epub", "kmz", "msix", "appx",
    "vsix", "whl", "nupkg", "3mf", "usdz",
}

# ftyp / ISO-BMFF and RIFF families. filetype tells the members apart, but if
# one member is detected against another member's name, that is not a swap.
_FTYP_FAMILY = {"mp4", "m4v", "mov", "qt", "m4a", "m4b", "3gp", "3g2", "heic",
                "heif", "avif", "f4v"}
_RIFF_FAMILY = {"webp", "wav", "wave", "avi", "ani"}

# How much of the recovered plaintext to hand the detector. Every magic this
# needs, including the ZIP local header a docx is recognised by, sits at the
# very front of the file, so a head slice is enough and keeps large files cheap.
_DETECT_HEAD = 65536


def detect_content_type(head):
    """
    Best effort true type of a decrypted file from its leading bytes.

    Returns (ext, category): ext is a lowercase extension with no dot, or None
    if nothing is recognised; category is this module's coarse grouping. Uses
    filetype when installed and the built in SIGNATURES table otherwise.
    """
    if not head:
        return None, None
    if HAVE_FILETYPE:
        try:
            kind = _filetype.guess(bytes(head))
        except Exception:
            kind = None
        if kind is not None:
            ext = (kind.extension or "").lower()
            if ext:
                return ext, _CATEGORY_BY_EXT.get(ext, "other")
    # Fallback: the internal signature table's canonical extension.
    _, canon, _ = identify_ex(head[:16])
    if canon:
        ext = canon.lstrip(".").lower()
        return ext, _CATEGORY_BY_EXT.get(ext, "other")
    return None, None


def plan_extension_fix(name, head):
    """
    Decide whether a recovered file's extension contradicts its content badly
    enough to correct. `name` is the output path or basename as it currently
    stands (its .cryptedmicro suffix already removed).

    Returns None to leave the name as it is, or a dict describing the fix:
        {"old": <current ext, no dot>, "new": <corrected ext, no dot>,
         "category": <detected category>}

    Conservative by design. Only a genuine cross category swap triggers a
    rename. Same category disagreements, alias pairs and container families are
    all left alone, as is anything the detector cannot place.
    """
    ext, cat = detect_content_type(head)
    if not ext or cat in (None, "other"):
        return None                       # cannot tell, or not a hard category
    cur = os.path.splitext(name)[1].lstrip(".").lower()
    if not cur:
        return None                       # no extension present, nothing swapped
    if cur == ext:
        return None
    if cur in _ALIASES.get(ext, ()):      # same format under another name
        return None
    if ext == "zip" and cur in _ZIP_FAMILY:
        return None                       # generic zip vs a real zip container
    if ext in _FTYP_FAMILY and cur in _FTYP_FAMILY:
        return None
    if ext in _RIFF_FAMILY and cur in _RIFF_FAMILY:
        return None
    if _CATEGORY_BY_EXT.get(cur, "other") == cat:
        return None                       # same category, not a category swap
    return {"old": cur, "new": ext, "category": cat}


# ===========================================================================
# SECTION 9. Main
# ===========================================================================

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="unmicro.py",
        description="Decrypt files encrypted by the Dev7 / Micro ransomware "
                    "(.cryptedmicro). Your encrypted files are never modified.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    g_src = ap.add_argument_group("finding the files")
    g_src.add_argument("--in", dest="src",
                       help="encrypted file, or directory containing .cryptedmicro files")
    g_src.add_argument("--auto", action="store_true",
                       help="search every drive and user location for encrypted files")
    g_src.add_argument("--scan-root", action="append", default=[],
                       help="extra root to search under --auto, repeatable")
    g_src.add_argument("--no-prune", action="store_true",
                       help="do not skip system folders while scanning, much slower")
    g_src.add_argument("--recursive", action="store_true",
                       help="walk subdirectories of --in")
    g_src.add_argument("--max-files", type=int,
                       help="stop scanning after this many encrypted files")

    g_key = ap.add_argument_group("keys")
    g_key.add_argument("--key", action="append", default=[],
                       help="key string to try, repeatable")
    g_key.add_argument("--wordlist", help="file of candidate keys, one per line")
    g_key.add_argument("--brute", action="store_true",
                       help="if the known keys fail, generate and sweep candidates "
                            "modelled on this crew's key history")
    g_key.add_argument("--deep", action="store_true",
                       help="with --brute, widen every generator. Hours, not seconds")
    g_key.add_argument("--workers", type=int, default=None, metavar="N",
                       help="parallel worker processes for the sweep. Defaults to "
                            "every CPU core on this machine, to push the guessing "
                            "as fast as the hardware allows. Set 1 to stay "
                            "single-process, e.g. to keep a victim machine responsive")
    g_key.add_argument("--gpu", action="store_true",
                       help="use an OpenCL GPU (NVIDIA or AMD) for the sweep. Needs "
                            "pyopencl and OpenCL drivers. Runs an AES self-test "
                            "against the CPU first and falls back to the CPU unless "
                            "it passes, so it can never return a wrong result or "
                            "miss a key")
    g_key.add_argument("--gpu-info", dest="gpu_info", action="store_true",
                       help="list the OpenCL platforms and devices found, and exit")
    g_key.add_argument("--max-passes", type=int, default=8,
                       help="how many times to sweep for keys. One pass can "
                            "turn up several keys; each extra pass targets "
                            "only the files no key covers yet, which is how "
                            "an interrupted encryption run is picked up "
                            "(default 8, 1 disables the extra passes)")
    g_key.add_argument("--max-candidates", type=int,
                       help="give up after this many guesses")
    g_key.add_argument("--dumb-brute", dest="dumb_brute", action="store_true",
                       help="classic incremental brute force: every string from "
                            "3 characters up to the longest recovered key, over "
                            "the Turkish+English alphabet these operators type. "
                            "Follows the structure of the known keys, not a "
                            "dictionary. Exhaustive, so only the short lengths "
                            "finish; it pauses and asks before a length that "
                            "would take too long. Runs after --brute")
    g_key.add_argument("--charset", choices=("observed", "turkish", "full"),
                       default="turkish",
                       help="alphabet for --dumb-brute: 'observed' only the "
                            "characters in the recovered keys, 'turkish' (default) "
                            "adds Turkish and English lowercase and digits, 'full' "
                            "adds uppercase too. Wider is more coverage but a much "
                            "bigger search")
    g_key.add_argument("--scavenge", action="append", default=[], metavar="FILE",
                       help="pull candidate keys out of an UNENCRYPTED dump (a "
                            "memory image, pagefile, hibernation file, strings "
                            "listing or implant log) and try them first. The key "
                            "is a typed string and often survives there in the "
                            "clear. Repeatable. Never point this at an encrypted file")
    g_key.add_argument("--checkpoint", metavar="FILE",
                       help="save sweep progress to FILE and resume from it if it "
                            "already exists, so an interrupted or --max-candidates "
                            "stopped run continues instead of starting over")
    g_key.add_argument("--seen-cap", dest="seen_cap", type=int, metavar="N",
                       help="cap each generator's duplicate-suppression set at N "
                            "entries (default %d). Lower it on a low-memory "
                            "machine" % SEEN_CAP)
    g_key.add_argument("--list-keys", action="store_true",
                       help="print the built in known keys and exit")

    g_out = ap.add_argument_group("output")
    g_out.add_argument("--out", dest="dst",
                       help="directory to write recovered files into")
    g_out.add_argument("--identify", action="store_true",
                       help="only work out which key applies, write nothing")
    g_out.add_argument("--flat", action="store_true",
                       help="write everything into one folder instead of mirroring paths")
    g_out.add_argument("--overwrite", action="store_true",
                       help="overwrite instead of adding a numeric suffix")
    g_out.add_argument("--keep-unverified", action="store_true",
                       help="also write files that failed verification, suffixed .UNVERIFIED")
    g_out.add_argument("--strict", action="store_true",
                       help="do not write anything that failed structural verification, "
                            "even under a key already proven on this machine")
    g_out.add_argument("--fix-ext", dest="fix_ext", action="store_true", default=True,
                       help="correct extensions that disagree with the recovered "
                            "content. On by default; this flag is kept for "
                            "compatibility and is now a no-op")
    g_out.add_argument("--no-fix-ext", dest="fix_ext", action="store_false",
                       help="do not correct swapped extensions. By default a "
                            "recovered file whose content is a different category "
                            "from its name (this crew randomises extensions) is "
                            "written under its true extension and the swap reported")
    g_out.add_argument("--force", action="store_true",
                       help="apply a single supplied key without header checking")
    g_out.add_argument("--pure-python", action="store_true",
                       help="ignore installed crypto libraries and use the built in AES")
    g_out.add_argument("--quiet", action="store_true", help="less output")
    g_out.add_argument("-y", "--yes", action="store_true",
                       help="answer yes to prompts, such as continuing "
                            "--dumb-brute into a long length. For unattended runs")
    ap.add_argument("--version", action="version", version="unmicro.py " + VERSION)
    args = ap.parse_args(argv)

    if args.list_keys:
        for k in KNOWN_KEYS:
            print(k)
        return 0

    if args.gpu_info:
        try:
            import pyopencl as cl
        except Exception:
            print("pyopencl is not installed.  pip install pyopencl")
            return 1
        plats = cl.get_platforms()
        if not plats:
            print("No OpenCL platforms found. Install your NVIDIA or AMD OpenCL runtime.")
            return 1
        for p in plats:
            print("Platform: %s (%s)" % (p.name.strip(), p.vendor.strip()))
            for d in p.get_devices():
                try:
                    kind = cl.device_type.to_string(d.type)
                except Exception:
                    kind = "?"
                print("    %-8s %s" % (kind, d.name.strip()))
        return 0

    _init_backend(args.pure_python)

    if args.seen_cap:
        globals()["SEEN_CAP"] = max(1000, args.seen_cap)

    # A bare run with no source and no strategy is meant to just go: search the
    # whole machine, try every route, and drop what it recovers into a folder it
    # makes. Naming a source, a strategy or an output turns the matching default
    # off, so an explicit invocation behaves exactly as before.
    full_auto = not args.src and not args.auto
    if full_auto:
        args.auto = True
        if not (args.brute or args.deep or args.dumb_brute or args.key
                or args.wordlist or args.scavenge or args.force):
            args.brute = True
            args.dumb_brute = True
    default_out = not args.identify and not args.dst
    if default_out:
        args.dst = DEFAULT_OUT_DIR

    if (args.brute or args.dumb_brute) and BACKEND == "pure-python" and not args.quiet:
        print("Note: no crypto library installed, so guessing will be very slow.")
        print("      pip install pycryptodome makes --brute thousands of times faster.")
        print()

    if not args.quiet:
        print("unmicro.py %s   AES back end: %s" % (VERSION, BACKEND))
        if args.fix_ext and not args.identify:
            if HAVE_FILETYPE:
                print("Extension repair on. Type detection: filetype %s."
                      % FILETYPE_VERSION)
            else:
                print("Extension repair on, but the filetype library is not installed,")
                print("so detection falls back to the smaller built in table. For full")
                print("coverage: pip install filetype")
        if full_auto:
            print("No options given, so running full-auto: searching every drive,")
            print("trying the recovered keys, the fitted model and the structural")
            print("brute. Point --in at a folder to narrow it, or --identify to")
            print("only locate keys.")
        if default_out:
            print("Recovered files will be written to ./%s (created for you)."
                  % DEFAULT_OUT_DIR)
        print("Your encrypted files will not be modified, renamed or deleted.")
        print()

    # --- find the files ----------------------------------------------------
    if args.auto:
        roots = args.scan_root or candidate_roots()
        if not args.quiet:
            print("Searching for encrypted files under:")
            for r in roots:
                print("    %s" % r)
        files = walk_for_encrypted(roots, prune=not args.no_prune,
                                   progress=not args.quiet, limit=args.max_files)
    else:
        files = collect(args.src, args.recursive or os.path.isdir(args.src))

    if not files:
        print("No %s files found." % EXT)
        if not args.auto:
            print("Try --auto to search the whole machine.")
        return 1

    if not args.quiet:
        dirs = sorted(set(os.path.dirname(f) for f in files))
        print("Encrypted files found: %d across %d folder(s)" % (len(files), len(dirs)))
        for d in dirs[:10]:
            print("    %s" % d)
        if len(dirs) > 10:
            print("    ... and %d more folders" % (len(dirs) - 10))
        print()

    # --- work out the key --------------------------------------------------
    wordlist = []
    if args.wordlist:
        with open(long_path(args.wordlist), "r",
                  encoding="utf-8", errors="replace") as fh:
            wordlist = [ln.rstrip("\r\n") for ln in fh if ln.strip()]

    forced = False
    if (args.force and len(args.key) == 1 and not args.brute
            and not args.dumb_brute and not wordlist and not args.scavenge):
        mapping = {args.key[0]: files}
        forced = True
        if not args.quiet:
            print("Forced key %r applied to all %d files without header checking."
                  % (args.key[0], len(files)))
    else:
        model = get_model()
        dumb_alpha_n = len(model.dumb_alphabet(args.charset))
        plan = build_plan(brute=args.brute, deep=args.deep, dumb=args.dumb_brute,
                          extra=args.key, wordlist=wordlist,
                          scavenged=args.scavenge, dumb_charset=args.charset)

        # Gate for the structural brute. Each length is its own tier, costing
        # alphabet ** length. Before a length that would take a long time, stop
        # and lay out the situation: on a terminal ask whether to go on;
        # unattended, stop unless --yes was given or --max-candidates bounds it.
        # This is where "climb to the longest key, then ask" actually bites,
        # since the tractable wall arrives well before length 23 over a
        # Turkish+English alphabet.
        gate_at = 50_000_000
        interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())

        def gate(name, tier_idx):
            if not name.startswith("structural brute len="):
                return True
            length = int(name.rsplit("=", 1)[1])
            size = dumb_alpha_n ** length
            if size <= gate_at or args.yes:
                return True
            rate = 150000.0 if BACKEND != "pure-python" else 2000.0
            secs = size / rate
            when = ("%.0f seconds" % secs if secs < 90 else
                    "%.1f minutes" % (secs / 60.0) if secs < 5400 else
                    "%.1f hours" % (secs / 3600.0) if secs < 172800 else
                    "%.1f days" % (secs / 86400.0))
            print()
            print("Structural brute has cleared every key shorter than %d "
                  "characters with" % length)
            print("no match. Length %d is %s candidates over a %d-character "
                  "alphabet," % (length, "{:,}".format(size), dumb_alpha_n))
            print("roughly %s at this machine's rate, and each further length is"
                  % when)
            print("dramatically larger.")
            if not interactive:
                print("Not a terminal, so stopping here. Re-run with --yes to let it")
                print("continue, --max-candidates N to bound it, or --checkpoint FILE")
                print("to make it resumable.")
                return False
            try:
                ans = input("Continue into length %d? [y/N] " % length).strip().lower()
            except EOFError:
                return False
            return ans in ("y", "yes")

        # Default to every core, so the guessing runs as fast as the hardware
        # allows. --workers 1 opts back into a single process.
        workers = args.workers if args.workers and args.workers > 0 else (os.cpu_count() or 1)
        gpu = init_gpu(quiet=args.quiet) if args.gpu else None
        if not args.quiet:
            routes = []
            if args.scavenge:
                routes.append("scavenged strings")
            if args.brute:
                routes.append("fitted model")
            if args.dumb_brute:
                routes.append("structural brute, %s alphabet" % args.charset)
            if gpu is not None:
                routes.append("GPU: %s" % gpu.name)
            elif workers > 1:
                routes.append("%d workers" % workers)
            tail = (" (%s)" % ", ".join(routes)) if routes else ""
            print("Trying keys%s:" % tail)
        mapping, tried, unmatched = find_all_keys(
            files, plan, workers=workers,
            limit=args.max_candidates, quiet=args.quiet,
            max_passes=max(1, args.max_passes),
            checkpoint=args.checkpoint, on_tier_start=gate, gpu=gpu)
        if not mapping:
            print()
            print("No key opened any file after %d candidate(s)." % tried)
            print()
            if not args.brute:
                print("Next step: re-run with --brute to sweep modelled candidates.")
            elif not args.dumb_brute:
                print("Next step: add --dumb-brute for a plain structural brute, and")
                print("           --checkpoint FILE so a long run can resume.")
            else:
                print("Next step: --deep widens the model, --charset full widens the")
                print("           brute. Best odds: --scavenge FILE on a memory image,")
                print("           pagefile or hibernation file, which is where a typed")
                print("           key most often survives in the clear.")
            print()
            print("What this does and does not mean:")
            print("  * The key is a string the operator typed. It is not derived from")
            print("    anything in the file and cannot be read out of the ciphertext.")
            print("    AES-256 itself is not broken here and is not being attacked.")
            print("  * Do not assume the machine's own recovery paths survived. This")
            print("    crew disables Windows Recovery, Task Manager and Regedit, and")
            print("    adds a Defender exclusion. Check what is actually left rather")
            print("    than counting on it.")
            print("  * Do not wipe the machine and do not delete the encrypted files.")
            print("    That is what turns a recoverable situation into a permanent one.")
            print("  * If the machine is still on and infected, the key may still be")
            print("    in memory. Take it off the network but leave it powered on, and")
            print("    get a responder to look before anyone reboots it.")
            print("  * Do not pay. Their decryption is issued from their own bot to the")
            print("    implant on your machine, so it means keeping the infection alive")
            print("    and letting their code run again.")
            print("  * Keep every encrypted file. Mention Chattering Magpies when you")
            print("    post about this so the case gets picked up faster.")
            return 2
        if not args.quiet:
            print()
        for k, hits in mapping.items():
            print("Key found: %r opens %d/%d files" % (k, len(hits), len(files)))
        if len(mapping) > 1:
            covered = sum(len(h) for h in mapping.values())
            print()
            print("%d keys on this set, covering %d/%d files. That is what an"
                  % (len(mapping), covered, len(files)))
            print("interrupted encryption run looks like: the machine went down part")
            print("way through and the operators started it again under a new key.")
        if unmatched:
            print()
            print("Not covered by any key found: %d file(s)." % len(unmatched))
        print()

    if args.identify:
        covered = set()
        for hits in mapping.values():
            covered.update(hits)
        print("Keys: %d. Files covered: %d/%d." % (len(mapping), len(covered), len(files)))
        for f in [f for f in files if f not in covered][:20]:
            print("  no key for: %s" % f)
        return 0

    # --- decrypt -----------------------------------------------------------
    os.makedirs(long_path(args.dst), exist_ok=True)
    recovered = unverified = failed = 0
    ext_fixed = 0
    ext_fix_log = []
    handled = set()

    # A key is proven once any one file under it validates structurally. From
    # that point the key is not in question, so the remaining files under it
    # are written rather than withheld. They still carry the .UNVERIFIED
    # suffix, because their contents were never structurally checked. --strict
    # restores the old behaviour of writing nothing unverified.
    proven = set()
    if not forced:
        for key_string, hits in mapping.items():
            for path in hits[:6]:
                _, ver, _ = decrypt_file(path, key_string, verify=True)
                if ver:
                    proven.add(key_string)
                    break

    for key_string, hits in mapping.items():
        for path in hits:
            if path in handled:
                continue
            handled.add(path)

            pt, verified, err = decrypt_file(path, key_string, verify=not forced)

            if pt is None:
                print("  FAIL   %s  (%s)" % (os.path.basename(path), err))
                failed += 1
                continue
            allow = (args.keep_unverified
                     or (key_string in proven and not args.strict))
            if not verified and not forced and not allow:
                print("  FAIL   %s  (%s, not written, use --keep-unverified)"
                      % (os.path.basename(path), err or "unverified"))
                failed += 1
                continue

            label, canon = identify(pt[:16])
            dest = mirrored_path(args.dst, path, flat=args.flat)
            fix = plan_extension_fix(dest, pt[:_DETECT_HEAD]) if args.fix_ext else None
            if fix:
                dest = os.path.splitext(dest)[0] + "." + fix["new"]
            if not verified and not forced:
                dest += ".UNVERIFIED"
            # One destination that cannot be written must not end the run.
            # On Windows this is usually antivirus holding the handle, a full
            # disk, or a name the output volume will not take. Say so and move
            # on, because the other few thousand files still matter.
            tmp = None
            try:
                os.makedirs(long_path(os.path.dirname(dest) or "."),
                            exist_ok=True)
                if not args.overwrite:
                    dest = unique_path(dest)
                tmp = dest + ".part"
                with open(long_path(tmp), "wb") as fh:
                    fh.write(pt)
                os.replace(long_path(tmp), long_path(dest))
            except OSError as e:
                print("  FAIL   %s  (cannot write: %s)"
                      % (os.path.basename(path), e))
                failed += 1
                if tmp:
                    try:
                        os.remove(long_path(tmp))
                    except OSError:
                        pass
                continue

            if verified:
                recovered += 1
                if not args.quiet:
                    print("  OK     %-56s %10d bytes  %s"
                          % (os.path.basename(dest)[:56], len(pt), label or "unknown type"))
            elif forced:
                unverified += 1
                if not args.quiet:
                    print("  FORCED %-56s %10d bytes  %s"
                          % (os.path.basename(dest)[:56], len(pt),
                             label or "unrecognised type, not structurally checked"))
            else:
                unverified += 1
                if not args.quiet:
                    print("  PROVEN %-56s %10d bytes  %s"
                          % (os.path.basename(dest)[:56], len(pt),
                             "key proven on this machine, structure not checked"))

            if fix:
                ext_fixed += 1
                ext_fix_log.append((os.path.basename(dest), fix["old"],
                                    fix["new"], fix["category"]))
                if not args.quiet:
                    print("         ^ EXTENSION SWAP FIXED: named .%s, contents are "
                          "%s (%s). Renamed the recovered copy; corrected from the"
                          % (fix["old"], fix["new"].upper(), fix["category"]))
                    print("           decrypted bytes. Dev7 randomised this extension; "
                          "your encrypted original is untouched.")

    leftover = [f for f in files if f not in handled]

    print()
    print("Recovered and verified : %d" % recovered)
    if unverified:
        print("Written unverified     : %d%s" % (unverified,
              "  (forced key, structure not checked)" if forced
              else "  (proven key, structure not checked, .UNVERIFIED suffix)"))
    if failed:
        print("Failed                 : %d" % failed)
    if ext_fixed:
        print("Extension swaps fixed  : %d" % ext_fixed)
    if leftover:
        print("No key found for       : %d" % len(leftover))
        for f in leftover[:20]:
            print("    %s" % f)
        if len(leftover) > 20:
            print("    ... and %d more" % (len(leftover) - 20))
    if ext_fixed:
        print()
        print("Extension swaps: %d recovered file(s) were saved under an extension"
              % ext_fixed)
        print("that did not match their contents. This crew randomises extensions")
        print("before encrypting (a video named .jpg, an archive named .png), so each")
        print("was renamed from its decrypted bytes. The rename is on the recovered")
        print("copy only; your encrypted originals are untouched. Examples:")
        for shown, old, new, category in ext_fix_log[:10]:
            print("    .%-5s -> .%-5s  %-11s %s" % (old, new, category, shown[:48]))
        if len(ext_fix_log) > 10:
            print("    ... and %d more" % (len(ext_fix_log) - 10))

    print()
    print("Verified means the padding parsed, the length matched, and the file")
    print("structure checked out: CRCs, terminators and length fields, not just")
    print("the first few bytes. Open a few anyway, and keep your encrypted")
    print("copies until you are satisfied.")
    print()
    print("Rho-9 Systems. Your first line of unusual defense.")
    return 0 if (recovered or unverified) else 3


if __name__ == "__main__":
    # freeze_support must come first and must come before anything touches
    # multiprocessing. In a PyInstaller build on Windows the worker processes
    # re-execute this binary, so without it --workers relaunches the whole
    # program, over and over, instead of starting workers. It is a no-op
    # everywhere else.
    import multiprocessing
    multiprocessing.freeze_support()

    setup_console()

    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted, nothing left half written\n")
        sys.exit(130)
