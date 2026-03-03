#!/usr/bin/env python3
"""
Decoder for Apator (APA) water meter readings from the W-MBus protocol.


Copyright (C) 2026 xmatekaj@proton.me

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.



Usage:
  python decode_wmbus.py --keys keys.csv --frames frames.xls
  python decode_wmbus.py --keys keys.csv --frames frames.csv
  python decode_wmbus.py --keys keys.csv --frames frames.xls --output results.csv

Keys file (CSV, separator ';'):
  Radio number;wMBUS key
  12345678;000102030405060708090A0B0C0D0E0F

Frames file (XLS or CSV):
  XLS: multi-column format (SOF | L | C | M | A | data blocks hex)
  CSV (separator ';'):
    Detail;Frame_hex
    Description;FF61440106785634121A07...

Frame format (binary):
  SOF(FF) + L + C + M(2B) + A(6B) + data_blocks_with_CRC
  Encryption: AES-128-CBC (mode 5), IV = M(2B) + A(6B) + TPL_ACC × 8
  After decryption: OMS DIF/VIF (2F 2F) + manufacturer data (Apator)
"""

import argparse
import calendar
import csv as csv_mod
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path
from Crypto.Cipher import AES

CRC_POLY = 0x3D65


# ---------------------------------------------------------------------------
# CRC-16 (wMBus, poly 0x3D65)
# ---------------------------------------------------------------------------

def _build_crc_table():
    table = []
    for i in range(256):
        crc, a = 0, (i << 8) & 0xFFFF
        for _ in range(8):
            if (crc ^ a) & 0x8000:
                crc = ((crc << 1) ^ CRC_POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
            a = (a << 1) & 0xFFFF
        table.append(crc)
    return table

_CRC_TABLE = _build_crc_table()

def crc16(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = (((crc & 0xFFFF) << 8) ^ _CRC_TABLE[((crc >> 8) ^ b) & 0xFF]) & 0xFFFF
    return crc

def check_wmbus_crc(block: bytes) -> bool:
    c = crc16(block[:-2])
    return ((c >> 8) & 0xFF) == (block[-2] ^ 0xFF) and (c & 0xFF) == (block[-1] ^ 0xFF)


# ---------------------------------------------------------------------------
# Block data extraction (strip CRC) from a raw wMBus frame
# ---------------------------------------------------------------------------

def extract_block_data(raw: bytes) -> bytes | None:
    """
    raw starts at the L-field.
    Verifies header and block CRCs, returns clean data (without CRC bytes).
    """
    if len(raw) < 12:
        return None
    l = raw[0]
    payload_len = l - 9
    if payload_len <= 0:
        return None
    n_blocks = -(-payload_len // 16)

    # Header: bytes 0..9 + CRC 10..11
    if not check_wmbus_crc(raw[0:12]):
        return None

    out = bytearray()
    off = 12
    for i in range(n_blocks):
        blen = 16 if (i < n_blocks - 1 or payload_len % 16 == 0) else payload_len % 16
        blk = raw[off: off + blen + 2]
        if len(blk) < blen + 2 or not check_wmbus_crc(blk):
            return None
        out.extend(blk[:blen])
        off += blen + 2
    return bytes(out)


# ---------------------------------------------------------------------------
# Frame loading from XLS / CSV
# ---------------------------------------------------------------------------

def hex_bytes(field: str) -> bytes:
    s = field.strip().replace(" ", "")
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s) if s else b""


def _load_frames_xls(path: Path) -> list[dict]:
    import xlrd
    wb = xlrd.open_workbook(str(path))
    ws = wb.sheet_by_index(0)
    frames = []
    for r in range(1, ws.nrows):
        row = [ws.cell_value(r, c) for c in range(ws.ncols)]
        detail = str(row[0]).strip()
        raw = bytearray()
        for c in range(2, ws.ncols):
            cell = str(row[c]).strip()
            if cell:
                try:
                    raw.extend(hex_bytes(cell))
                except ValueError:
                    pass
        if len(raw) < 14:
            continue
        frames.append({"detail": detail, "raw": bytes(raw)})
    return frames


def _load_frames_csv(path: Path) -> list[dict]:
    """
    CSV with columns: Detail;Frame_hex
    Frame_hex – full frame as a hex string (no spaces).
    """
    frames = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv_mod.reader(f, delimiter=";")
        header = next(reader)
        h = [c.strip().lower() for c in header]
        try:
            i_det = next(i for i, c in enumerate(h) if "detail" in c)
            i_hex = next(i for i, c in enumerate(h) if "frame" in c or "hex" in c)
        except StopIteration:
            raise ValueError(
                f"Frames CSV must have 'Detail' and 'Frame_hex' columns, found: {header}"
            )
        for row in reader:
            if len(row) <= max(i_det, i_hex):
                continue
            detail = row[i_det].strip()
            raw_hex = row[i_hex].strip().replace(" ", "")
            if not raw_hex:
                continue
            try:
                raw = bytes.fromhex(raw_hex)
            except ValueError:
                continue
            if len(raw) < 14:
                continue
            frames.append({"detail": detail, "raw": raw})
    return frames


def load_frames(path: Path) -> list[dict]:
    if path.suffix.lower() in (".xls", ".xlsx"):
        return _load_frames_xls(path)
    return _load_frames_csv(path)


def parse_raw_frame(raw: bytes) -> dict | None:
    """
    Parses raw bytes from XLS/CSV.
    Frame format: SOF(FF) + L + C + M(2B) + A(6B) + blocks_with_CRC
    Header block CRC is NOT included in the XLS (data starts from the CI field).
    Block data (with their CRCs) follows directly after the A-field.
    """
    # raw[0] = SOF = 0xFF (added by USB receiver, not part of W-MBus)
    # raw[1] = L-field
    # raw[2] = C-field
    # raw[3..4] = M-field (2B)
    # raw[5..10] = A-field (6B: ID[4] + SW + HW)
    # raw[11..] = data blocks with CRC (without header CRC)
    if raw[0] != 0xFF or len(raw) < 12:
        return None

    l_field  = raw[1]
    m_bytes  = raw[3:5]     # M-field (manufacturer code)
    a_bytes  = raw[5:11]    # A-field: ID(4) + SW(1) + HW(1)
    id_bytes = a_bytes[0:4]
    sw       = a_bytes[4]
    hw       = a_bytes[5]

    # Radio number: ID bytes reversed, decoded as BCD
    radio_bcd = bytes([id_bytes[3], id_bytes[2], id_bytes[1], id_bytes[0]])
    try:
        radio_num = int("".join(f"{b:02X}" for b in radio_bcd))
    except ValueError:
        radio_num = 0

    # Block data (with data block CRCs, without header CRC)
    raw_blocks_with_crc = raw[11:]
    payload_len = l_field - 9
    if payload_len <= 0:
        return None
    n_blocks = -(-payload_len // 16)

    # Extract block_data (strip data block CRCs)
    out = bytearray()
    off = 0
    ok = True
    for i in range(n_blocks):
        blen = 16 if (i < n_blocks - 1 or payload_len % 16 == 0) else payload_len % 16
        blk = raw_blocks_with_crc[off: off + blen + 2]
        if len(blk) < blen + 2:
            ok = False; break
        if not check_wmbus_crc(blk):
            ok = False; break
        out.extend(blk[:blen])
        off += blen + 2

    if not ok:
        # Fallback: use raw data without CRC stripping
        block_data = raw_blocks_with_crc[:payload_len]
    else:
        block_data = bytes(out)

    return {
        "l_field":    l_field,
        "m_bytes":    m_bytes,
        "a_bytes":    a_bytes,
        "sw":         sw,
        "hw":         hw,
        "radio_num":  radio_num,
        "block_data": block_data,
        "crc_ok":     ok,
    }


# ---------------------------------------------------------------------------
# AES-128-CBC decryption
# ---------------------------------------------------------------------------

def build_iv(m: bytes, a: bytes, tpl_acc: int) -> bytes:
    """IV = M(2B) + A(6B) + TPL_ACC × 8"""
    return m + a + bytes([tpl_acc & 0xFF] * 8)

def decrypt_cbc(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    if not ct or len(ct) % 16 != 0:
        return None
    try:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OMS DIF/VIF parser
# ---------------------------------------------------------------------------

# VIF → volume multiplier in m³ (0x10..0x17), per EN 13757-3:
# exponent = (VIF & 0x07) - 6  → VIF=0x10→10^-6, VIF=0x13→10^-3, VIF=0x17→10^1
_VOL_VIFS = {v: 10 ** ((v & 0x07) - 6) for v in range(0x10, 0x18)}

def _type_f_datetime(b: bytes) -> datetime | None:
    """Decodes a 4-byte OMS Type F datetime."""
    if len(b) < 4:
        return None
    min_  =  b[0] & 0x3F
    hour_ =  b[1] & 0x1F
    day_  =  b[2] & 0x1F
    yr_lo = (b[2] >> 5) & 0x07
    mon_  =  b[3] & 0x0F
    yr_hi = (b[3] >> 4) & 0x07
    year  = 2000 + (yr_hi << 3 | yr_lo)
    try:
        return datetime(year, mon_, day_, hour_, min_)
    except (ValueError, OverflowError):
        return None

def _read_int_le(b: bytes) -> int:
    return int.from_bytes(b, "little")

# Data size by DIF field (bits 3:0)
_DIF_SIZE = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 4, 6: 6, 7: 8,
             8: 0, 9: 1, 10: 2, 11: 3, 12: 4, 13: -1, 14: 6, 15: -2}


def parse_oms_payload(payload: bytes) -> dict:
    """
    Parses the decrypted OMS payload (after the 2F 2F verification bytes).
    Returns: volume_m3, timestamp, faults_word, history[], extra_hex
    """
    result = {
        "volume_m3":  None,
        "timestamp":  None,
        "faults_word": None,
        "history": [],
        "extra_hex":   "",
    }

    i = 0
    # Skip OMS verification bytes 2F 2F
    while i < len(payload) and payload[i] == 0x2F:
        i += 1

    while i < len(payload):
        if i >= len(payload):
            break
        dif = payload[i]; i += 1

        # Idle/fill byte
        if dif == 0x2F:
            continue

        dif_data = dif & 0x0F
        dif_func = (dif >> 4) & 0x03
        has_dife = bool(dif & 0x80)

        # Skip DIFE extension bytes
        while has_dife and i < len(payload):
            dife = payload[i]; i += 1
            has_dife = bool(dife & 0x80)

        # Special DIF function
        if dif_data == 0x0F:
            # DIF=0x0F: manufacturer-specific data (Apator)
            # Structure: VIF (1B) + alarm_word (4B LE) + info (nB)
            if i + 5 <= len(payload):
                vif_mfr = payload[i]; i += 1
                alarm = _read_int_le(payload[i:i+4]); i += 4
                result["faults_word"] = alarm
                # Remaining manufacturer bytes (unknown structure)
                extra = payload[i:]
                result["extra_hex"] = extra.hex().upper()
                # Try to extract monthly history from the remaining bytes.
                # Pattern: ~8B header, then 4-byte LE volume values.
                # Heuristic: look for a sequence of decreasing 4-byte values.
                _try_extract_history(result, extra)
            break

        # Regular DIF record
        n = _DIF_SIZE.get(dif_data, 0)
        if n < 0:
            # LVAR or unsupported – stop parsing
            break
        if i >= len(payload):
            break

        # VIF
        vif = payload[i]; i += 1
        while (vif & 0x80) and i < len(payload):
            vif = payload[i]; i += 1
        vif_clean = vif & 0x7F

        val_bytes = payload[i:i+n]; i += n

        # Volume
        if vif_clean in _VOL_VIFS and n == 4:
            v = _read_int_le(val_bytes) * _VOL_VIFS[vif_clean]
            if result["volume_m3"] is None:
                result["volume_m3"] = round(v, 4)

        # Type F timestamp
        elif vif_clean == 0x6D and n == 4:
            if result["timestamp"] is None:
                result["timestamp"] = _type_f_datetime(val_bytes)

    return result


def _month_end(year: int, month: int) -> datetime:
    """Returns the last day of the given month at 23:59."""
    last_day = calendar.monthrange(year, month)[1]
    return datetime(year, month, last_day, 23, 59)


def _prev_month(year: int, month: int) -> tuple[int, int]:
    if month == 1:
        return year - 1, 12
    return year, month - 1


def _try_extract_history(result: dict, extra: bytes):
    """
    Heuristic: search for a sequence of 4-byte LE volume values in the
    manufacturer-specific data, after an 8-12 byte header (Apator).
    Values are expected to be less than the current reading (newest first).
    """
    cur = result.get("volume_m3") or 0
    max_impulses = int(cur * 1000) + 1  # max units (0.001 m³ each)

    for start in range(0, min(20, len(extra)), 2):
        vals = []
        off = start
        while off + 4 <= len(extra):
            v = _read_int_le(extra[off:off+4])
            if v == 0 or v > max_impulses + 10000:
                break
            vals.append(round(v * 0.001, 3))
            off += 4
        if len(vals) >= 3:
            # Compute dates going back month by month from the reading date
            ts = result.get("timestamp")
            if ts:
                dates = []
                y, m = ts.year, ts.month
                for _ in vals:
                    y, m = _prev_month(y, m)
                    dates.append(_month_end(y, m))
            else:
                dates = [None] * len(vals)
            result["history"] = [{"date": d, "volume_m3": v}
                                  for d, v in zip(dates, vals)]
            return


# ---------------------------------------------------------------------------
# Alarm / fault decoding
# ---------------------------------------------------------------------------

_FAULTS_CURRENT = {
    15: "Flow below minimum",
    14: "Flow above maximum",
    13: "Reverse flow",
    12: "No flow",
    11: "Water leak",
    10: "Disconnection",
     9: "Magnetic field",
}
_FAULTS_MEMORY = {
     8: "Low battery",
     7: "Flow below minimum (hist.)",
     6: "Flow above maximum (hist.)",
     5: "Reverse flow (hist.)",
     4: "No flow (hist.)",
     3: "Water leak (hist.)",
     2: "Disconnection (hist.)",
     1: "Magnetic field (hist.)",
     0: "Battery lifetime exceeded",
}

def decode_faults(word: int | None) -> list[str]:
    if word is None:
        return []
    if word == 0:
        return ["OK"]
    msgs = []
    for bit, name in sorted({**_FAULTS_CURRENT, **_FAULTS_MEMORY}.items(), reverse=True):
        if word & (1 << bit):
            msgs.append(name)
    return msgs


# ---------------------------------------------------------------------------
# Loading AES keys from CSV
# ---------------------------------------------------------------------------

def load_keys(path: Path) -> dict[int, bytes]:
    keys: dict[int, bytes] = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv_mod.reader(f, delimiter=";")
        header = next(reader)
        ir = header.index("Numer radiowy")
        ik = header.index("Klucz wMBUS")
        for row in reader:
            try:
                radio = int(row[ir].strip())
                key_h = row[ik].strip()
                if len(key_h) == 32:
                    keys[radio] = bytes.fromhex(key_h)
            except (ValueError, IndexError):
                pass
    return keys


# ---------------------------------------------------------------------------
# Main processing loop
# ---------------------------------------------------------------------------

def process_frame(frame_dict: dict, keys: dict) -> dict | None:
    """Processes one frame. Returns a result dict or None on parse failure."""
    raw = frame_dict["raw"]
    parsed = parse_raw_frame(raw)
    if not parsed:
        return None

    radio = parsed["radio_num"]
    key   = keys.get(radio)
    if not key:
        return {"status": "no_key", "radio_num": radio, **{k: parsed[k] for k in ("sw", "hw", "block_data")}}

    bd = parsed["block_data"]
    ci = bd[0] if bd else 0

    # Handle CI=0x8C (ELL I) + application CI=0x7A (short TPL, mode 5)
    if ci == 0x8C and len(bd) >= 8 and bd[3] == 0x7A:
        tpl_acc  = bd[4]
        tpl_cfg  = (bd[7] << 8) | bd[6]
        sec_mode = (tpl_cfg >> 8) & 0x1F
        n_enc    = (tpl_cfg >> 4) & 0x0F
        if sec_mode != 5:
            return {"status": "unsupported_sec_mode", "radio_num": radio}
        encrypted = bd[8: 8 + n_enc * 16] if n_enc else bd[8:]
    else:
        return {"status": "unsupported_ci", "radio_num": radio, "ci": ci}

    # Decryption
    encrypted_aligned = encrypted[: (len(encrypted) // 16) * 16]
    if len(encrypted_aligned) < 16:
        return {"status": "too_short", "radio_num": radio}

    iv        = build_iv(parsed["m_bytes"], parsed["a_bytes"], tpl_acc)
    plaintext = decrypt_cbc(key, iv, encrypted_aligned)
    if not plaintext or plaintext[0] != 0x2F:
        return {"status": "decrypt_failed", "radio_num": radio}

    # OMS parsing
    oms = parse_oms_payload(plaintext)

    return {
        "status":     "ok",
        "radio_num":  radio,
        "sw":         parsed["sw"],
        "hw":         parsed["hw"],
        "volume_m3":  oms["volume_m3"],
        "timestamp":  oms["timestamp"],
        "faults":     decode_faults(oms["faults_word"]),
        "faults_word": oms["faults_word"],
        "history":    oms["history"],
        "iv":         iv.hex().upper(),
        "plaintext":  plaintext.hex().upper(),
        "crc_ok":     parsed["crc_ok"],
    }


def main():
    ap = argparse.ArgumentParser(
        description="Decoder for Apator W-MBus water meter readings (AES-128-CBC, OMS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --keys example_keys.csv --frames example_frames.csv\n"
            "  %(prog)s -k keys.csv -f frames.xls -o results.csv\n"
        ),
    )
    ap.add_argument("-k", "--keys",   required=True, metavar="FILE",
                    help="AES keys CSV (columns: 'Numer radiowy', 'Klucz wMBUS')")
    ap.add_argument("-f", "--frames", required=True, metavar="FILE",
                    help="Frames file: .xls/.xlsx (multi-column format) or .csv (Detail;Frame_hex)")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="Output CSV file (default: decoded_readings.csv next to the script)")
    args = ap.parse_args()

    keys_path   = Path(args.keys)
    frames_path = Path(args.frames)
    out_path    = Path(args.output) if args.output else Path(__file__).parent / "decoded_readings.csv"

    for p in (keys_path, frames_path):
        if not p.exists():
            sys.exit(f"Error: file not found: {p}")

    print("=" * 70)
    print(" W-MBus Decoder – Apator APA water meters")
    print("=" * 70)

    keys       = load_keys(keys_path)
    print(f"\nLoaded {len(keys)} keys from: {keys_path}")

    raw_frames = load_frames(frames_path)
    print(f"Loaded {len(raw_frames)} frames from: {frames_path}\n")

    results    = []
    stats      = {"ok": 0, "no_key": 0, "error": 0}

    for idx, rf in enumerate(raw_frames, 1):
        r = process_frame(rf, keys)
        label = rf["detail"][:40]

        if r is None:
            stats["error"] += 1
            print(f"[{idx:3d}] PARSE ERROR      | {label}")
            continue

        radio = r.get("radio_num", 0)
        status = r.get("status", "?")

        if status == "no_key":
            stats["no_key"] += 1
            sw, hw = r.get("sw", 0), r.get("hw", 0)
            ci = r.get("block_data", b"\x00")[0] if r.get("block_data") else 0
            print(f"[{idx:3d}] NO KEY           | ID={radio:>10d}  SW={sw:02X} HW={hw:02X}  CI={ci:02X}")
            continue

        if status != "ok":
            stats["error"] += 1
            print(f"[{idx:3d}] {status:<16} | ID={radio:>10d}")
            continue

        stats["ok"] += 1
        vol  = r["volume_m3"]
        ts   = r["timestamp"].strftime("%Y-%m-%d %H:%M") if r["timestamp"] else "N/A"
        flt  = ", ".join(r["faults"]) or "–"
        hist_entries = r["history"]
        if hist_entries:
            hist = "  ".join(
                f"{e['date'].strftime('%Y-%m-%d') if e['date'] else '?'}: {e['volume_m3']:.3f}"
                for e in hist_entries[:6]
            )
        else:
            hist = "–"

        print(f"[{idx:3d}] ID={radio:>10d}  {label}")
        print(f"       Volume:    {vol:>10.3f} m³")
        print(f"       Date:      {ts}")
        print(f"       Alarms:    {flt}")
        if hist_entries:
            print(f"       History:   {hist} m³")
        print()

        results.append({
            "Radio_number": radio,
            "Details":      rf["detail"][:60],
            "Volume_m3":    f"{vol:.3f}" if vol is not None else "",
            "Reading_date": ts,
            "Alarms":       flt,
            "Fault_word":   f"0x{r['faults_word']:08X}" if r["faults_word"] is not None else "",
            "History_m3":   "; ".join(
                f"{e['date'].strftime('%Y-%m-%d') if e['date'] else '?'}: {e['volume_m3']:.3f}"
                for e in r["history"]
            ),
            "CRC_OK":       str(r["crc_ok"]),
        })

    print("=" * 70)
    print(f"Summary: OK={stats['ok']}  No key={stats['no_key']}  Error={stats['error']}")

    if results:
        with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv_mod.DictWriter(f, fieldnames=list(results[0].keys()), delimiter=";")
            w.writeheader()
            w.writerows(results)
        print(f"\nResults ({len(results)} readings) saved → {out_path}")


if __name__ == "__main__":
    main()
