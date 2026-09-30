# unmicro

Free decryptor for files encrypted by the **Dev7 / Micro** ransomware family,
the ones renamed to `.cryptedmicro`.

Built and maintained by **Rho-9 Systems**. Your first line of unusual defense.

This tool is free and will stay free.

If it does not recover your files, we may offer to take the case further as a
paid engagement. That work is hands on and it costs time and money, so it is
not something we can give away by default. If you cannot afford it, say so
when you get in touch.

---

## If you have just been hit, read this first

1. **Do not pay.** There is no guarantee of recovery and it funds the next
   round of victims.
2. **Their "decryption" is not something you can run.** It is a command the
   operators issue from their own bot to the implant still on your machine, so
   it requires keeping the infection alive and letting their code execute
   again. That is a second reason not to pay, on top of the first one.
3. **Do not wipe the machine and do not delete the encrypted files.** That is
   the one thing that turns a recoverable situation into a permanent loss, and
   it is the first thing people reach for. Removing the malware does not harm
   the encrypted files. Copy them to an external drive before anything else.
4. **If the machine is still on and still infected, leave it powered on** and
   take it off the network instead. The key is a string the operator typed,
   and it may still be sitting in memory.
5. **Do not assume the machine's own recovery paths survived.** This crew
   disables Windows Recovery, Task Manager and Regedit, and adds a Defender
   exclusion. Check what is actually left rather than counting on it, and get
   an incident responder to look if you can.

When you post about this anywhere, use the phrase **Chattering Magpies**. That
is Rho-9's actor name for this crew, and it is what lets cases be found and
triaged quickly.

---

## Getting the tool

There are three ways to run unmicro. They take exactly the same options and
recover exactly the same files. Pick the one that fits the machine.

| build | for | needs |
| --- | --- | --- |
| `unmicro-<version>-windows-x86_64.exe` | Windows, 64 bit | nothing |
| `unmicro-<version>-linux-x86_64` | Linux, 64 bit x86 | glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+, RHEL 9+) |
| `unmicro.py` | anything else, including Termux, ARM Linux and macOS | Python 3 |

The two binaries are built by GitHub Actions straight from this repository and
published on the [Releases](https://github.com/Rho-9-Official/Dev7-decryptor/releases)
page. They have a compiled AES back end bundled inside, so they are fast out of
the box and `--brute` is practical without installing anything.

**Only download unmicro from this repository.** A copy of a "decryptor" handed
to you anywhere else is exactly what a second attacker would send a victim.

If the infected machine is still on and off the network, as recommended above,
do the download on a clean machine, verify it there, and carry it across on a
USB drive. Do not reconnect the infected machine just to fetch the tool.

### Windows (recommended command)

Run this in PowerShell, in an empty folder. It resolves the latest release,
pulls the binary and the checksum file from this repository, and refuses to
continue if the checksum does not match.

```powershell
$repo = "https://github.com/Rho-9-Official/Dev7-decryptor"
$tag  = (curl.exe -fsSLI -o NUL -w "%{url_effective}" "$repo/releases/latest").Split('/')[-1]
$f    = "unmicro-$($tag.TrimStart('v'))-windows-x86_64.exe"
curl.exe -fLO "$repo/releases/download/$tag/$f"
curl.exe -fLO "$repo/releases/download/$tag/SHA256SUMS"
$want = ((Select-String -Path SHA256SUMS -Pattern $f -SimpleMatch).Line -split '\s+')[0]
$got  = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
if ($got -eq $want) { "checksum OK" } else { throw "CHECKSUM MISMATCH, do not run $f" }
& ".\$f" --auto --out recovered
```

Type `curl.exe`, not `curl`. In Windows PowerShell 5.1, plain `curl` is an alias
for a different command and the flags above will not work with it.
`curl.exe` ships with Windows 10 (1803 and later) and Windows 11.

Windows SmartScreen may say the file is unrecognised. The binary is not code
signed, so this is expected. Verify the checksum as above, then choose
**More info** and **Run anyway**.

### Linux (recommended command)

```bash
repo=https://github.com/Rho-9-Official/Dev7-decryptor
tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest"); tag=${tag##*/}
f="unmicro-${tag#v}-linux-x86_64"
curl -fLO "$repo/releases/download/$tag/$f"
curl -fLO "$repo/releases/download/$tag/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS && chmod +x "$f" && "./$f" --auto --out ./recovered
```

`sha256sum` prints `OK` next to the file name when it matches. If it prints
`FAILED`, the `&&` chain stops and nothing is run.

This binary is x86_64 only. On ARM Linux, a Raspberry Pi, or anything with a
glibc older than 2.35, use the Python source below.

### Python source (Termux, ARM, macOS, or if you would rather read the code first)

```bash
git clone https://github.com/Rho-9-Official/Dev7-decryptor.git
cd Dev7-decryptor
python3 unmicro.py --auto --out ./recovered
```

No git? Pull the single file instead:

```bash
curl -fLO https://raw.githubusercontent.com/Rho-9-Official/Dev7-decryptor/main/unmicro.py
python3 unmicro.py --auto --out ./recovered
```

On Termux, `pkg install python git` first if they are not already installed.

### Verifying build provenance (optional)

Every release binary carries a GitHub build attestation tying it to the exact
commit and workflow run that produced it. With the GitHub CLI installed:

```
gh attestation verify <file> --repo Rho-9-Official/Dev7-decryptor
```

A pass means the file was built by this repository's own workflow, not
uploaded by hand.

---

## Quick start

The examples below use the Python form. Every option works identically on the
binaries, so swap the start of the line for whichever build you have:

| build | start of the command |
| --- | --- |
| Python | `python3 unmicro.py` |
| Windows binary | `.\unmicro-<version>-windows-x86_64.exe` |
| Linux binary | `./unmicro-<version>-linux-x86_64` |

```
# find the files yourself and try the recovered keys
python3 unmicro.py --auto --out ./recovered

# point it at a folder instead
python3 unmicro.py --in ./encrypted --out ./recovered

# you already know the key
python3 unmicro.py --in ./encrypted --out ./recovered --key zarox

# the recovered keys did not fit, so start guessing
python3 unmicro.py --in ./encrypted --out ./recovered --brute

# guess harder, takes much longer
python3 unmicro.py --in ./encrypted --out ./recovered --brute --deep --workers 4
```

Run any build with `--version` to see which release you have.

## Requirements

**Binaries:** nothing. Python is not needed and nothing has to be installed.
The fast AES back end is already inside.

**Python source:** Python 3 and nothing else. If `pycryptodome` or
`cryptography` is installed it will be used and will be much faster, but a
complete AES-256 implementation is built into the file, so the tool runs on a
bare interpreter. That includes Termux on Android.

```
pip install pycryptodome     # optional, strongly recommended before --brute
```

The built in implementation is far slower than a compiled back end. It is fine
for trying the recovered keys, but if you intend to use `--brute`, install
`pycryptodome` or use a binary.

`--pure-python` forces the built in implementation even when a library is
available.

The first line of output always reports which back end is in use, for example
`AES back end: pycryptodome`.

**Extension repair** (see below) uses the `filetype` library when it is present.
It is pure Python with no other dependencies, so it installs cleanly on Termux
and is bundled into the released binaries.

```
pip install filetype        # recommended, for the broadest type detection
```

Without it the tool still runs and still repairs extensions, but falls back to a
smaller built-in signature table and says so on the second line of output.

---

## Correcting swapped extensions

This crew has started **randomising file extensions** before encrypting, so a
recovered file's name is no longer a reliable guide to what it is: a video can
arrive named `.jpg`, an archive named `.png`. Decryption is unaffected, but the
recovered file would otherwise be written under a misleading name that will not
open by double-click.

After each file decrypts, unmicro reads its true type from the recovered bytes.
If the name's extension genuinely contradicts the content it writes the output
under the corrected extension and reports the swap, for example:

```
  OK     holiday.mp4                                88 bytes  MP4/MOV
         ^ EXTENSION SWAP FIXED: named .jpg, contents are MP4 (video). Renamed
           the recovered copy; corrected from the decrypted bytes.
```

This is a **naming repair on the recovered copy only**. The recovered bytes are
never altered and the encrypted originals are never touched.

It is deliberately conservative, because a careless rename makes a recovery
worse. Many correct names share magic bytes with something else: a `.docx` is a
ZIP, a `.mov` and a `.m4a` share the `.mp4` box structure, a `.wav` and a
`.webp` are both RIFF. So a rename happens **only** when the content sits in a
different category from the extension, for example an image name over video
bytes. A same-category disagreement (a `.png` named `.jpg`) is left alone, and
so is any container family where the current name is already a valid member.

On by default. Pass `--no-fix-ext` to turn it off and keep the original names.

---

## What it will and will not do to your files

* Your encrypted files are **never modified, renamed or deleted**. They are
  opened read only. Recovered files are written somewhere else entirely.
* Recovered files mirror their original directory layout under `--out`, so a
  whole machine sweep does not collapse thousands of files into one folder
  and clobber same named files. `--flat` overrides this.
* Nothing is overwritten. A name collision gets a numeric suffix unless you
  pass `--overwrite`.
* **This tool only decrypts.** There is no encrypt path in it anywhere. The
  AES back ends expose decryption only and the built in AES has no
  `encrypt_block`. It cannot produce a `.cryptedmicro` file.

---

## What "verified" means

A key that produces the right first few bytes has not proved anything. Short
magic numbers collide: `BM` is two bytes, so a wrong key hits it roughly once
in every 65,536 guesses. So every recovery is checked against the real
structure of the file before it counts:

* PKCS#5 padding parses and the recovered length agrees with the ciphertext
* PNG chunk CRCs, JPEG and GIF terminators, BMP length fields, ZIP central
  directories, gzip trailers, PE headers, ID3 sizes, OLE2 headers
* plain text is validated by decoding as UTF-8 with a printable character
  ratio, which is safe because a wrong key yields uniformly random bytes and
  random bytes of any real length are valid UTF-8 with vanishing probability

Three outcomes appear in the output:

| marker | meaning |
| --- | --- |
| `OK` | decrypted and structurally verified |
| `PROVEN` | the key was proved on another file on this machine, this file decrypted cleanly but its format is not one the tool can structurally check. Written with a `.UNVERIFIED` suffix |
| `FAIL` | not written |

The `PROVEN` case exists because withholding it was losing real data. Files
with no magic number, meaning text, CSV, source code, config files and
anything not in the signature table, used to be reported as "no key found"
even when the key was already proved on the same machine. On the test corpus
that was 90 files out of 463. A key is only ever treated as proven after at
least one file under it validates structurally, so this never asserts a key
that has not been demonstrated.

`--strict` restores the old behaviour and writes nothing that failed
structural verification. `--keep-unverified` goes the other way and writes
everything that decrypted, proven key or not.

**Keep your encrypted copies until you have opened the recovered files and
confirmed they are right.** Do not delete anything on the strength of this
tool alone.

---

## How the key search works

The malware derives its AES key with no KDF, no IV, no salt and no per file
state:

```
key        = Arrays.copyOf(keyString.getBytes(UTF_8), 32)
cipher     = AES/ECB/PKCS5Padding
ciphertext = encrypt(entire file)
```

One operator typed string covers every file the walker touched on that
machine. That single design choice is what makes recovery by guessing
practical at all: one AES key schedule and one block per candidate, instead of
the hundred thousand PBKDF2 rounds a competent implementation would have used.

AES-256 itself is **not** broken here and is not being attacked. The key is a
string a person typed. It is not derived from anything in the file and cannot
be read out of the ciphertext.

The candidate generator is fitted from the 34 keys recovered from the
operators' own Discord C2. Nothing in it is hand ranked. The character
alphabets, the length prior, the affix widths, the tiling motifs and the share
of the sweep each family receives are all measured from those keys. The
families are:

| family | share | what it covers |
| --- | --- | --- |
| digit | 32.4% | tilings and rotations of a short motif over the observed digit alphabet, plus fumbled tilings |
| word | 26.5% | Turkish and English words with folding and short affixes |
| motor | 23.5% | keyboard runs, reversals and zigzags on the Turkish Q layout |
| stem | 17.6% | operator handle or word plus a digit tail |

Two things the fit ruled out, recorded here so nobody rebuilds them:

* A **positional mask model** does not work on this data. The fitted masks are
  dominated by `l9`, `d15`, `d16`, `l11` and `l13`, whose enumeration spaces
  are 5.1e11 to 8.2e16. Observed key length runs 5 to 23 with a mean of 11, so
  the tractable short masks are exactly the ones these operators do not use.
* A **character bigram** suffers the degenerate repeat pathology. Its highest
  scoring strings are `1111111111111111` and `KKKKKKKK`, and fitted on all 34
  keys it surfaced only 8 of them in the first million candidates.

---

## How well it works

Measured by leave one out: refit the model without each recovered key in turn,
then find where that key lands in the stream it would actually be swept in. A
model scored against keys it was fitted on is scoring its own memory.

Result: **14 of 34** within a 2,000,000 candidate budget, at roughly 1.3M
candidates per second generated.

The measurement harness is deliberately not shipped in the tool. Nothing in
`unmicro.py` exists except to recover files.

### Known gaps

These are real and are not regressions:

* **Uppercase mashes.** Keys like `KŞL132KŞL2KŞL432`, `qwkewqkeqwk` and
  `WQEŞİQW2ELŞ12` are motor noise over a twelve character alphabet at lengths
  8 to 17. Nothing reaches them at any budget tested. A Turkish Q adjacency
  walker was built and measured for this family, reached none of the confirmed
  mash keys inside 3M candidates, and was removed rather than left in taking
  budget from the families that work.
* **Vocabulary.** A key built on a name the vocabulary does not contain is
  unreachable no matter how candidates are ordered. Coverage of the stem and
  word families is vocabulary, not structure. Adding names to `TURKISH_VOCAB`
  is the cheapest way to improve this tool.
* `keyu3131` is missed. The honest route to it is stem mutation, not a
  hardcoded prefix copied out of the key itself.

---

## What's new in 3.5

- **Extension repair.** Recovered files are written under their true extension.
  This crew randomises extensions before encrypting (a video named `.jpg`), so
  unmicro reads the decrypted bytes and corrects a genuinely mismatched
  extension, reporting each one. On by default; `--no-fix-ext` turns it off.
- **`--scavenge FILE`.** Pulls candidate keys out of an unencrypted dump (memory
  image, pagefile, hibernation file, strings listing) and tries them first,
  where a typed key most often survives in the clear.
- **`--dumb-brute`.** A plain structural brute, 3 characters up to the longest
  recovered key, over the Turkish+English alphabet these operators type
  (`--charset`). Pauses and asks before a length that would take too long.
- **Bounded-memory sweep.** A long `--brute`/`--dumb-brute` run now holds flat
  memory instead of growing without bound (`--seen-cap`), which fixes an
  out-of-memory kill on deep runs.
- **`--checkpoint FILE`.** Save sweep progress and resume, skipping finished
  tiers and fast-forwarding the current one.
- **Full-auto.** A bare `python3 unmicro.py` searches every drive, tries every
  route, and writes to `./unmicro-recovered`.
- **All cores by default.** `--workers` now defaults to every CPU core; set 1 to
  stay single-process.
- **`--gpu` (experimental).** OpenCL sweep for NVIDIA and AMD, self-tested
  against the CPU. See below.

## GPU acceleration (optional, experimental)

The sweep is one AES-256 decrypt per candidate, which is exactly what a GPU is
good at. `--gpu` runs the guessing on an OpenCL device, which covers both NVIDIA
and AMD from one kernel.

```
pip install pyopencl        # plus your NVIDIA or AMD OpenCL runtime
python3 unmicro.py --gpu-info                       # what OpenCL sees
python3 unmicro.py --in ./encrypted --out ./rec --brute --gpu
```

It is opt-in, and safe by construction for a recovery tool. Key derivation stays
on the CPU, so nothing is mis-encoded on the device. Before the GPU is trusted
for a single real candidate, it decrypts random blocks under random keys and
compares every byte against the CPU AES back end; a single mismatch disables the
GPU and the run continues on the CPU. Every GPU hit is re-decrypted and
re-validated on the CPU before it counts. So the GPU can make the search faster,
or on hardware where the kernel does not hold up simply not engage. It cannot
make the search wrong or cause a key to be missed.

This path is **new and experimental in 3.5**. The kernel's AES-256 logic was
verified against a reference AES on random vectors, but the OpenCL execution
itself should be confirmed on your own card: run `--gpu` and look for the line
`GPU ready: <device> (AES self-test passed against the CPU back end)`. If you
see a self-test failure instead, it has already fallen back to the CPU.

## Options worth knowing

| flag | effect |
| --- | --- |
| (no options) | search every drive, try every route, write to `./unmicro-recovered` |
| `--auto` | search every drive and user location for encrypted files |
| `--brute` | sweep generated candidates when the recovered keys do not fit |
| `--deep` | widen every family, including the layout walker. Hours, not seconds |
| `--dumb-brute` | plain structural brute force, 3 chars up to the longest key, over the Turkish+English alphabet. Asks before a length that would take too long |
| `--charset observed\|turkish\|full` | alphabet for `--dumb-brute` (default `turkish`: Turkish and English lowercase and digits) |
| `--scavenge FILE` | pull candidate keys out of an unencrypted dump (memory image, pagefile, strings listing) and try them first. Repeatable |
| `--checkpoint FILE` | save sweep progress and resume from it, so an interrupted or capped run continues |
| `--seen-cap N` | cap each generator's dedup set at N entries (default 1,000,000). Lower on a low-memory machine |
| `--workers N` | parallel worker processes for the sweep. Defaults to every CPU core; set 1 to stay single-process |
| `--gpu` | use an OpenCL GPU (NVIDIA or AMD) for the sweep. Self-tests against the CPU first and falls back if it fails |
| `--gpu-info` | list the OpenCL platforms and devices found, and exit |
| `--max-candidates N` | give up after N guesses |
| `--yes` | answer yes to prompts, for unattended runs |
| `--identify` | work out which key applies and write nothing |
| `--wordlist FILE` | try your own candidates first, one per line |
| `--no-fix-ext` | stop correcting swapped extensions (this crew randomises them, so the correction is on by default) |
| `--strict` | never write anything that failed structural verification |
| `--force` | apply a single supplied key without header checking |
| `--list-keys` | print the recovered keys and exit |

---

## Who this crew is

| name | what it refers to |
| --- | --- |
| **Chattering Magpies** | Rho-9's actor name for the operators. Use this in posts |
| **Micro** | what the malware calls itself |
| **Dev7** | the family designation |
| **Remote Sense** | the current disposable bot identity, not a durable name |

MAGPIES is Rho-9's category noun for financially motivated extortion crews.
Delivery has been observed through trojanized Minecraft mods in CurseForge
packs, and through files posing as games.

## Getting help

Reply or DM wherever you saw the Rho-9 post about this. Include the phrase
Chattering Magpies so the case is routed quickly.

If this tool recovered your files, that is the end of it and you owe nobody
anything. If it did not, keep the encrypted copies and get in touch. There may
be more we can do, some of it as paid work, and we would rather hear from you
than have you delete the only copies that can still be recovered.
