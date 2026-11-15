// Excel + PDF list of files that were NOT backed up: executables, plus files that failed the
// content checks in safety.rs (disguised files, PDFs with scripts/attachments, ...).
// Both formats are hand-written to stay stdlib-only: the .xlsx is a minimal stored (uncompressed)
// zip of SpreadsheetML parts, the .pdf is plain Helvetica text pages.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

// What counts as "executable" for the report.
pub const EXEC: &[&str] = &["exe", "dll", "msi", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta", "lnk", "jar", "scr", "com", "pif"];

pub struct Exe {
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
    pub reason: String,
}

pub fn is_exec(p: &Path) -> bool {
    p.extension().is_some_and(|e| EXEC.iter().any(|k| e.eq_ignore_ascii_case(k)))
}

// Writes `<dir>/_blocked.xlsx` and `<dir>/_blocked.pdf`, overwriting the last run's.
pub fn write(dir: &Path, src: &Path, exes: &mut [Exe]) -> io::Result<()> {
    exes.sort_by(|a, b| a.path.cmp(&b.path));
    let rows: Vec<_> = exes
        .iter()
        .map(|e| {
            let p = e.path.display().to_string();
            vec![Cell::T(p), Cell::T(ext(&e.path)), Cell::T(e.reason.clone()), Cell::N(e.size), Cell::T(date(e.modified))]
        })
        .collect();
    let cols = [("Path", 100.0), ("Type", 8.0), ("Why it was blocked", 45.0), ("Size (bytes)", 14.0), ("Modified (UTC)", 18.0)];
    fs::write(dir.join("_blocked.xlsx"), xlsx(&cols, &rows))?;
    let title = format!(
        "Files NOT backed up (executables / unsafe content) from {} - {} files - generated {} UTC",
        src.display(),
        exes.len(),
        date(SystemTime::now())
    );
    fs::write(dir.join("_blocked.pdf"), pdf(&title, exes))
}

fn ext(p: &Path) -> String {
    p.extension().unwrap_or_default().to_string_lossy().to_lowercase()
}

// UTC "YYYY-MM-DD HH:MM" (Hinnant's civil_from_days). ponytail: UTC, local time needs an OS API.
fn date(t: SystemTime) -> String {
    let s = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (z, rem) = (s.div_euclid(86400) + 719468, s.rem_euclid(86400));
    let (era, doe) = (z.div_euclid(146097), z.rem_euclid(146097));
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

fn xml_esc(s: &str) -> String {
    s.chars()
        .filter(|&c| c >= ' ' || c == '\t') // control chars are invalid XML
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            c => c.to_string(),
        })
        .collect()
}

pub enum Cell {
    T(String),
    N(u64),
}

// One-sheet workbook: header row (frozen) + rows. `cols` = (header, column width).
pub fn xlsx(cols: &[(&str, f32)], rows: &[Vec<Cell>]) -> Vec<u8> {
    const NS: &str = "http://schemas.openxmlformats.org";
    let col = |j: usize| (b'A' + j as u8) as char; // ponytail: max 26 columns
    let cell = |j: usize, r: usize, c: &Cell| match c {
        Cell::T(v) => format!(r#"<c r="{}{r}" t="inlineStr"><is><t>{}</t></is></c>"#, col(j), xml_esc(v)),
        Cell::N(v) => format!(r#"<c r="{}{r}"><v>{v}</v></c>"#, col(j)),
    };
    let widths: String = cols.iter().enumerate().map(|(j, (_, w))| format!(r#"<col min="{0}" max="{0}" width="{w}" customWidth="1"/>"#, j + 1)).collect();
    let header: String = cols.iter().enumerate().map(|(j, (h, _))| cell(j, 1, &Cell::T(h.to_string()))).collect();
    let mut sheet = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="{NS}/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>{widths}</cols><sheetData><row r="1">{header}</row>"#
    );
    for (i, row) in rows.iter().enumerate() {
        let r = i + 2;
        sheet += &format!(r#"<row r="{r}">"#);
        for (j, c) in row.iter().enumerate() {
            sheet += &cell(j, r, c);
        }
        sheet += "</row>";
    }
    sheet += "</sheetData></worksheet>";

    let rels = |target: &str, kind: &str| {
        format!(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{NS}/package/2006/relationships"><Relationship Id="rId1" Type="{NS}/officeDocument/2006/relationships/{kind}" Target="{target}"/></Relationships>"#)
    };
    let ct = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="{NS}/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#
    );
    let wb = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="{NS}/spreadsheetml/2006/main" xmlns:r="{NS}/officeDocument/2006/relationships"><sheets><sheet name="Executables" sheetId="1" r:id="rId1"/></sheets></workbook>"#
    );
    zip(&[
        ("[Content_Types].xml", ct),
        ("_rels/.rels", rels("xl/workbook.xml", "officeDocument")),
        ("xl/workbook.xml", wb),
        ("xl/_rels/workbook.xml.rels", rels("worksheets/sheet1.xml", "worksheet")),
        ("xl/worksheets/sheet1.xml", sheet),
    ])
}

// Stored (method 0) zip. ponytail: no zip64, so the sheet must stay < 4 GB (~20M rows; Excel caps at 1M).
fn zip(files: &[(&str, String)]) -> Vec<u8> {
    let (mut out, mut cd) = (vec![], vec![]);
    for (name, data) in files {
        let (crc, n, off) = (crc32(data.as_bytes()), data.len() as u32, out.len() as u32);
        let common = |v: &mut Vec<u8>| {
            // version needed, flags, method=stored, time, date=1980-01-01
            for x in [20u16, 0, 0, 0, 0x21] {
                v.extend(x.to_le_bytes());
            }
            for x in [crc, n, n] {
                v.extend(x.to_le_bytes());
            }
            v.extend((name.len() as u16).to_le_bytes());
            v.extend(0u16.to_le_bytes()); // extra len
        };
        out.extend(0x04034b50u32.to_le_bytes());
        common(&mut out);
        out.extend(name.as_bytes());
        out.extend(data.as_bytes());

        cd.extend(0x02014b50u32.to_le_bytes());
        cd.extend(20u16.to_le_bytes()); // version made by
        common(&mut cd);
        cd.extend([0u8; 10]); // comment len, disk, internal + external attrs
        cd.extend(off.to_le_bytes());
        cd.extend(name.as_bytes());
    }
    let (cd_off, cd_len, count) = (out.len() as u32, cd.len() as u32, files.len() as u16);
    out.extend(cd);
    out.extend(0x06054b50u32.to_le_bytes());
    out.extend([0u8; 4]); // disk numbers
    for x in [count, count] {
        out.extend(x.to_le_bytes());
    }
    for x in [cd_len, cd_off] {
        out.extend(x.to_le_bytes());
    }
    out.extend(0u16.to_le_bytes()); // comment len
    out
}

fn crc32(d: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in d {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 };
        }
    }
    !c
}

// PDF string literal in WinAnsi (≈ Latin-1); chars Helvetica can't show become '?'.
fn pdf_str(s: &str) -> Vec<u8> {
    let mut v = vec![b'('];
    for c in s.chars() {
        match c {
            '(' | ')' | '\\' => v.extend([b'\\', c as u8]),
            ' '..='~' | '\u{a0}'..='\u{ff}' => v.push(c as u32 as u8),
            _ => v.push(b'?'),
        }
    }
    v.push(b')');
    v
}

// A4 landscape, 48 rows per page.
fn pdf(title: &str, exes: &[Exe]) -> Vec<u8> {
    const PER_PAGE: usize = 48;
    let pages: Vec<&[Exe]> = if exes.is_empty() { vec![&[]] } else { exes.chunks(PER_PAGE).collect() };
    let n = pages.len();
    let kids: String = (0..n).map(|i| format!("{} 0 R ", 4 + 2 * i)).collect();
    let mut objs: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        format!("<< /Type /Pages /Kids [{kids}] /Count {n} >>").into_bytes(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_vec(),
    ];
    for (i, rows) in pages.iter().enumerate() {
        let mut s = vec![];
        let mut put = |x: u32, y: u32, size: u32, t: &str| {
            s.extend(format!("BT /F1 {size} Tf {x} {y} Td ").as_bytes());
            s.extend(pdf_str(t));
            s.extend(b" Tj ET\n");
        };
        put(36, 559, 11, title);
        put(740, 559, 9, &format!("page {} / {n}", i + 1));
        for (x, h) in [(36, "Modified (UTC)"), (116, "Size"), (166, "Why it was blocked"), (370, "Path")] {
            put(x, 538, 8, h);
        }
        for (j, e) in rows.iter().enumerate() {
            let y = 524 - 10 * j as u32;
            let p = e.path.display().to_string();
            // ~95 chars fit; keep the tail, it holds the file name.
            let p = match p.char_indices().rev().nth(91) {
                Some((k, _)) if p.chars().count() > 95 => format!("...{}", &p[k..]),
                _ => p,
            };
            let why: String = e.reason.chars().take(44).collect();
            put(36, y, 8, &date(e.modified));
            put(116, y, 8, &format!("{} KB", e.size.div_ceil(1024)));
            put(166, y, 8, &why);
            put(370, y, 8, &p);
        }
        if rows.is_empty() {
            put(36, 524, 8, "Nothing was blocked.");
        }
        objs.push(
            format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>", 5 + 2 * i)
                .into_bytes(),
        );
        let mut c = format!("<< /Length {} >>\nstream\n", s.len()).into_bytes();
        c.extend(s);
        c.extend(b"\nendstream");
        objs.push(c);
    }
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offs = vec![];
    for (i, o) in objs.iter().enumerate() {
        offs.push(out.len());
        out.extend(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend(o);
        out.extend(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offs {
        out.extend(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_and_crc() {
        assert_eq!(date(UNIX_EPOCH), "1970-01-01 00:00");
        assert_eq!(date(UNIX_EPOCH + std::time::Duration::from_secs(1_709_210_096)), "2024-02-29 12:34");
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }
}
