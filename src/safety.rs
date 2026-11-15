// Content checks run before a file is backed up. Returns Some(reason) to block it.
// Fail closed: anything that can't be fully inspected is blocked, never copied "just in case".

use std::{collections::BTreeSet, fs, io::{self, Read}, path::Path};

pub fn risk(path: &Path) -> io::Result<Option<String>> {
    let ext = path.extension().unwrap_or_default().to_string_lossy().to_lowercase();
    if ext == "pdf" {
        return Ok(pdf_risk(&fs::read(path)?));
    }
    let mut head = Vec::with_capacity(1 << 16);
    fs::File::open(path)?.take(1 << 16).read_to_end(&mut head)?;
    Ok(head_risk(&ext, &head))
}

fn image(h: &[u8]) -> bool {
    let tiff = [&b"II*\0"[..], b"MM\0*", b"IIRO", b"IIRS", b"MMOR", b"IIU\0"]; // TIFF and TIFF-based RAWs
    h.starts_with(&[0xff, 0xd8, 0xff])
        || h.starts_with(b"\x89PNG\r\n\x1a\n")
        || tiff.iter().any(|m| h.starts_with(m))
        || h.starts_with(b"FUJIFILM")
        || (h.starts_with(b"RIFF") && h.get(8..12) == Some(b"WEBP"))
        || h.starts_with(b"GIF87a")
        || h.starts_with(b"GIF89a")
        || h.starts_with(b"BM")
        || (h.get(4..8) == Some(b"ftyp") && h.get(8..12).is_some_and(|b| [&b"heic"[..], b"heix", b"mif1", b"msf1", b"heim", b"heis", b"avif", b"crx "].contains(&b)))
}

// The first bytes must be what the extension claims: a renamed .exe or .zip never gets through.
fn head_risk(ext: &str, h: &[u8]) -> Option<String> {
    for (magic, what) in [(&b"MZ"[..], "a Windows program"), (b"PK", "a zip archive"), (b"\x7fELF", "a program"), (b"Rar!", "a rar archive"), (b"7z\xbc\xaf", "a 7z archive")] {
        if h.starts_with(magic) {
            return Some(format!("disguised: .{ext} is really {what}"));
        }
    }
    let ok = match ext {
        // Any real image header is fine for any photo extension: a PNG saved as .jpg is common
        // and harmless. Anything that isn't an image is not.
        "jpg" | "jpeg" | "png" | "tif" | "tiff" | "dng" | "cr2" | "nef" | "arw" | "orf" | "rw2" | "raf"
        | "webp" | "gif" | "bmp" | "heic" | "heif" | "cr3" => image(h),
        "mp4" => h.get(4..8) == Some(b"ftyp"),
        "mp3" => h.starts_with(b"ID3") || (h.len() > 1 && h[0] == 0xff && h[1] & 0xe0 == 0xe0),
        "txt" => !h.contains(&0), // text has no NUL bytes (ponytail: rejects UTF-16 .txt files)
        _ => false,
    };
    (!ok).then(|| format!("contents don't match .{ext}"))
}

// PDF names that mean active content. ponytail: keyword-level check (like pdfid), not a full
// parser; a viewer bug exploited by a pure image/font is out of its reach. Open PDFs from the
// backup with JavaScript off if that matters.
const RISKY: [(&str, &str); 9] = [
    ("JavaScript", "JavaScript"),
    ("Launch", "launches programs"),
    ("EmbeddedFile", "embedded files"),
    ("EmbeddedFiles", "embedded files"),
    ("RichMedia", "embedded Flash/media"),
    ("XFA", "XFA form (can run scripts)"),
    ("SubmitForm", "sends data out"),
    ("ImportData", "imports data"),
    ("GoToE", "opens embedded files"),
];
const FILTERS: [&str; 6] = ["ASCIIHexDecode", "ASCII85Decode", "LZWDecode", "RunLengthDecode", "DCTDecode", "DecodeParms"];
const INFLATE_LIMIT: usize = 256 << 20; // decompression-bomb guard

pub fn pdf_risk(d: &[u8]) -> Option<String> {
    if !d.starts_with(b"%PDF-") {
        return Some("not a real PDF (bad header)".into());
    }
    // Long names are checked over the whole file, binary streams too. Short ones (/XFA) only
    // outside streams, where random compressed bytes can't fake them.
    let mut hits: BTreeSet<&str> = names(d).into_iter().filter(|n| n.len() >= 6).collect();
    let mut pos = 0;
    while pos < d.len() {
        let Some(s) = find(d, pos, b"stream") else {
            hits.extend(names(&d[pos..]));
            break;
        };
        if s >= 3 && &d[s - 3..s] == b"end" {
            hits.extend(names(&d[pos..s]));
            pos = s + 6;
            continue;
        }
        let text = &d[pos..s];
        hits.extend(names(text));
        let dict = names(&text[text.windows(3).rposition(|w| w == b"obj").unwrap_or(0)..]);
        let mut body = s + 6;
        body += d[body..].starts_with(b"\r") as usize;
        body += d[body..].starts_with(b"\n") as usize;
        let end = find(d, body, b"endstream").unwrap_or(d.len());
        // Object streams pack many objects (where /JavaScript etc. would sit) into one
        // compressed blob, so they must be unpacked to be checked.
        if dict.contains("ObjStm") {
            if dict.iter().any(|n| FILTERS.contains(n)) {
                return Some("can't inspect: unusual compression".into());
            }
            let objs = if dict.contains("FlateDecode") { zlib(&d[body..end]) } else { Some(d[body..end].to_vec()) };
            match objs {
                Some(o) => hits.extend(names(&o)),
                None => return Some("can't inspect: corrupt object stream".into()),
            }
        }
        pos = end + 9;
    }
    if hits.contains("Encrypt") {
        return Some("encrypted, can't be inspected".into());
    }
    let found: BTreeSet<&str> = RISKY.iter().filter(|(n, _)| hits.contains(n)).map(|(_, why)| *why).collect();
    (!found.is_empty()).then(|| format!("PDF has {}", found.into_iter().collect::<Vec<_>>().join(", ")))
}

fn find(d: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    d.get(from..)?.windows(pat.len()).position(|w| w == pat).map(|i| i + from)
}

// The PDF names (/Name, with #xx escapes decoded so /J#61vaScript can't dodge) that we care about.
fn names(d: &[u8]) -> BTreeSet<&'static str> {
    let watch = RISKY.iter().map(|r| r.0).chain(FILTERS).chain(["ObjStm", "FlateDecode", "Encrypt"]);
    let watch: Vec<&'static str> = watch.collect();
    let delim = |c: u8| c.is_ascii_whitespace() || c == 0 || b"()<>[]{}/%".contains(&c);
    let (mut out, mut i, mut n) = (BTreeSet::new(), 0, Vec::with_capacity(64));
    while i < d.len() {
        if d[i] != b'/' {
            i += 1;
            continue;
        }
        n.clear();
        i += 1;
        while i < d.len() && !delim(d[i]) && n.len() <= 64 {
            let hex = d.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
            match (d[i], hex) {
                (b'#', Some(v)) => {
                    n.push(v);
                    i += 3;
                }
                (c, _) => {
                    n.push(c);
                    i += 1;
                }
            }
        }
        if let Some(w) = watch.iter().find(|w| w.as_bytes() == n.as_slice()) {
            out.insert(*w);
        }
    }
    out
}

fn zlib(d: &[u8]) -> Option<Vec<u8>> {
    // 2-byte header: deflate method, no preset dictionary
    (d.len() > 2 && d[0] & 0x0f == 8 && d[1] & 0x20 == 0).then_some(())?;
    inflate(&d[2..], INFLATE_LIMIT)
}

// Minimal DEFLATE decoder (RFC 1951, after zlib's puff.c). None on bad data or > limit bytes.
fn inflate(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    let (mut b, mut out) = (Bits { d: data, pos: 0, buf: 0, cnt: 0 }, vec![]);
    loop {
        let last = b.need(1)?;
        match b.need(2)? {
            0 => {
                (b.buf, b.cnt) = (0, 0); // drop the partial byte
                let p = b.pos;
                let len = u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
                out.extend_from_slice(data.get(p + 4..p + 4 + len)?);
                b.pos = p + 4 + len;
            }
            1 => {
                let mut l = [8u8; 288];
                l[144..256].fill(9);
                l[256..280].fill(7);
                codes(&mut b, &mut out, &Huff::new(&l), &Huff::new(&[5; 30]), limit)?;
            }
            2 => {
                let (nlen, ndist, ncode) = (b.need(5)? as usize + 257, b.need(5)? as usize + 1, b.need(4)? as usize + 4);
                const ORD: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
                let mut cl = [0u8; 19];
                for &i in &ORD[..ncode] {
                    cl[i] = b.need(3)? as u8;
                }
                let ch = Huff::new(&cl);
                let mut lens = vec![];
                while lens.len() < nlen + ndist {
                    let (v, n) = match ch.decode(&mut b)? {
                        s @ 0..=15 => (s as u8, 1),
                        16 => (*lens.last()?, 3 + b.need(2)?),
                        17 => (0, 3 + b.need(3)?),
                        18 => (0, 11 + b.need(7)?),
                        _ => return None,
                    };
                    lens.extend(std::iter::repeat_n(v, n as usize));
                }
                if lens.len() != nlen + ndist {
                    return None;
                }
                codes(&mut b, &mut out, &Huff::new(&lens[..nlen]), &Huff::new(&lens[nlen..]), limit)?;
            }
            _ => return None,
        }
        if out.len() > limit {
            return None;
        }
        if last == 1 {
            return Some(out);
        }
    }
}

struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl Bits<'_> {
    fn need(&mut self, n: u32) -> Option<u32> {
        while self.cnt < n {
            self.buf |= (*self.d.get(self.pos)? as u32) << self.cnt;
            self.pos += 1;
            self.cnt += 8;
        }
        let v = self.buf & ((1u32 << n) - 1);
        self.buf >>= n;
        self.cnt -= n;
        Some(v)
    }
}

struct Huff {
    count: [u16; 16],
    sym: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Huff {
        let mut count = [0u16; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut offs = [0u16; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + count[i];
        }
        let mut sym = vec![0; lengths.len()];
        for (s, &l) in lengths.iter().enumerate().filter(|(_, l)| **l != 0) {
            sym[offs[l as usize] as usize] = s as u16;
            offs[l as usize] += 1;
        }
        Huff { count, sym }
    }

    fn decode(&self, b: &mut Bits) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.need(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return self.sym.get((index + code - first) as usize).copied();
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

const LBASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

fn codes(b: &mut Bits, out: &mut Vec<u8>, lit: &Huff, dist: &Huff, limit: usize) -> Option<()> {
    loop {
        match lit.decode(b)? as usize {
            s @ 0..=255 => out.push(s as u8),
            256 => return Some(()),
            s => {
                let s = s - 257;
                let len = *LBASE.get(s)? as usize + b.need(*LEXT.get(s)? as u32)? as usize;
                let ds = dist.decode(b)? as usize;
                let d = *DBASE.get(ds)? as usize + b.need(*DEXT.get(ds)? as u32)? as usize;
                if d > out.len() || out.len() + len > limit {
                    return None;
                }
                for _ in 0..len {
                    out.push(out[out.len() - d]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn inflates_all_block_types() {
        assert_eq!(zlib(&hex("7801010700f8ff73746f726564210bef02b3")).unwrap(), b"stored!");
        assert_eq!(zlib(&hex("78da4b4c4a4e4442002df505bf")).unwrap(), b"abcabcabcabcabc"); // fixed + back-refs
        let dynamic = zlib(include_bytes!("../testdata/objstm_ok.zlib")).unwrap();
        assert_eq!(dynamic, include_bytes!("../testdata/objstm_ok.txt"));
        assert!(zlib(b"\x78\x9c\xff\xff\xff").is_none());
    }

    fn pdf(objstm: &[u8], extra: &str) -> Vec<u8> {
        let mut d = format!("%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R{extra}>>\nendobj\n5 0 obj\n<</Type/ObjStm/N 3/First 9/Filter/FlateDecode/Length {}>>\nstream\n", objstm.len()).into_bytes();
        d.extend(objstm);
        d.extend(b"\nendstream\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF\n");
        d
    }

    #[test]
    fn pdf_checks() {
        let ok = include_bytes!("../testdata/objstm_ok.zlib");
        assert_eq!(pdf_risk(&pdf(ok, "")), None); // links (/URI) are fine
        // JavaScript hidden (and #-escaped) inside a compressed object stream, plus an attachment
        let bad = pdf_risk(&pdf(include_bytes!("../testdata/objstm_bad.zlib"), "")).unwrap();
        assert!(bad.contains("JavaScript") && bad.contains("embedded files"), "{bad}");
        assert!(pdf_risk(&pdf(ok, "/OpenAction<</S/Launch/F(cmd.exe)>>")).unwrap().contains("launches"));
        assert!(pdf_risk(&pdf(ok, "/AcroForm<</XFA 7 0 R>>")).unwrap().contains("XFA"));
        assert!(pdf_risk(&pdf(ok, "/Encrypt 9 0 R")).unwrap().contains("encrypted"));
        assert!(pdf_risk(&pdf(b"\x78\x9cgarbage", "")).unwrap().contains("can't inspect"));
        assert!(pdf_risk(b"MZ\x90\0%PDF-1.4").unwrap().contains("bad header"));
    }

    #[test]
    fn magic_bytes() {
        assert_eq!(head_risk("jpg", b"\xff\xd8\xff\xe0JFIF"), None);
        assert!(head_risk("jpg", b"MZ\x90\0").unwrap().contains("Windows program"));
        assert!(head_risk("png", b"PK\x03\x04").unwrap().contains("zip"));
        assert!(head_risk("mp4", b"\0\0\0\x20ftypisom").is_none() && head_risk("mp4", b"RIFF....").is_some());
        assert!(head_risk("mp3", b"ID3\x04").is_none() && head_risk("txt", b"hello\n").is_none());
        assert!(head_risk("txt", b"\x00\x01binary").is_some());
        assert!(head_risk("tiff", b"II*\0\x08").is_none() && head_risk("tif", b"MM\0*").is_none());
        assert!(head_risk("nef", b"MM\0*").is_none() && head_risk("heic", b"\0\0\0\x18ftypheic").is_none());
        assert!(head_risk("webp", b"RIFF\0\0\0\0WEBPVP8 ").is_none() && head_risk("webp", b"RIFF\0\0\0\0AVI ").is_some());
        assert!(head_risk("gif", b"\x89PNG\r\n\x1a\n").is_none()); // mislabeled image: fine
        assert!(head_risk("heic", b"\0\0\0\x18ftypisom").is_some()); // a video renamed .heic
        assert!(head_risk("jpg", b"%PDF-1.7").is_some() && head_risk("png", b"<html>").is_some());
    }
}
