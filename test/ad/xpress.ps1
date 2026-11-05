# Vectors for pac/xpress from Windows' own compressor: ntdll's
# RtlCompressBuffer with COMPRESSION_FORMAT_XPRESS (3) and
# COMPRESSION_FORMAT_XPRESS_HUFF (4), standard and maximum engines, over
# inputs of many sizes and kinds (random, runs, text, claims-like UTF-16).
# Each line: format engine size input-hex compressed-hex.
#
#   powershell -ExecutionPolicy Bypass -File xpress.ps1 -Out C:\Goose\xpress.txt

param([string]$Out = "C:\Goose\xpress.txt")
$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Xca {
    [DllImport("ntdll.dll")]
    static extern uint RtlGetCompressionWorkSpaceSize(ushort format, out uint bufWs, out uint fragWs);
    [DllImport("ntdll.dll")]
    static extern uint RtlCompressBuffer(ushort format, byte[] src, uint srcSize, byte[] dst, uint dstSize,
                                         uint chunk, out uint finalSize, byte[] ws);
    [DllImport("ntdll.dll")]
    static extern uint RtlDecompressBufferEx(ushort format, byte[] dst, uint dstSize, byte[] src, uint srcSize,
                                             out uint finalSize, byte[] ws);
    public static byte[] Compress(ushort format, byte[] src) {
        uint bws, fws;
        uint st = RtlGetCompressionWorkSpaceSize(format, out bws, out fws);
        if (st != 0) throw new Exception("workspace " + st.ToString("x"));
        byte[] ws = new byte[bws];
        byte[] dst = new byte[2 * src.Length + 65536];
        uint n;
        st = RtlCompressBuffer(format, src, (uint)src.Length, dst, (uint)dst.Length, 4096, out n, ws);
        // STATUS_BUFFER_TOO_SMALL: Windows will not compress some small
        // inputs (it gives up when the output would not be smaller).
        if (st == 0xC0000023) return null;
        if (st != 0) throw new Exception("compress " + st.ToString("x"));
        byte[] r = new byte[n];
        Array.Copy(dst, r, n);
        // Windows' own decompressor must give the input back.
        byte[] back = new byte[src.Length];
        uint m;
        byte[] dws = new byte[fws > 0 ? fws : 1];
        st = RtlDecompressBufferEx((ushort)(format & 0xff), back, (uint)back.Length, r, (uint)r.Length, out m, dws);
        if (st != 0 || m != src.Length) throw new Exception("decompress " + st.ToString("x"));
        for (int i = 0; i < src.Length; i++) if (back[i] != src[i]) throw new Exception("round trip");
        return r;
    }
}
"@

function Hex([byte[]]$b) { if ($b.Length -eq 0) { return "-" } ([System.BitConverter]::ToString($b)).Replace("-", "").ToLower() }

$rng = New-Object System.Random 20261103
function Make([string]$kind, [int]$n) {
    $b = New-Object byte[] $n
    switch ($kind) {
        "random" { $rng.NextBytes($b) }
        "zeros" { }
        "runs" { $v = 0; for ($i = 0; $i -lt $n; $i++) { if ($rng.Next(16) -eq 0) { $v = $rng.Next(256) }; $b[$i] = [byte]$v } }
        "text" {
            $words = "the quick brown fox jumps over lazy dogs ad://ext/department:88d5de791e7b27e6 kerberos claims pac".Split(" ")
            $s = New-Object System.Text.StringBuilder
            while ($s.Length -lt $n) { [void]$s.Append($words[$rng.Next($words.Length)]).Append(" ") }
            $b = [System.Text.Encoding]::ASCII.GetBytes($s.ToString().Substring(0, $n))
        }
        "utf16" {
            $s = New-Object System.Text.StringBuilder
            while ($s.Length * 2 -lt $n) { [void]$s.Append("ad://ext/attr" + $rng.Next(1000) + ":88d5de79" + $rng.Next(100000).ToString("x") + " ") }
            $b = [System.Text.Encoding]::Unicode.GetBytes($s.ToString()); $b = $b[0..($n - 1)]
        }
        "mixed" { $rng.NextBytes($b); for ($i = 0; $i -lt $n; $i++) { if (($i / 512) % 2 -eq 1) { $b[$i] = [byte](($i * 7) % 13) } } }
    }
    return [byte[]]$b
}

$sizes = 1, 2, 3, 4, 7, 15, 16, 17, 31, 64, 100, 255, 256, 257, 1000, 4095, 4096, 4097, 10000, 65535, 65536, 65537, 70000, 131072, 200000
$lines = New-Object System.Collections.Generic.List[string]
$skipped = ""
foreach ($format in 3, 4) {
    foreach ($engine in 0, 0x100) {
        foreach ($kind in "random", "zeros", "runs", "text", "utf16", "mixed") {
            foreach ($n in $sizes) {
                if ($kind -eq "random" -and $n -gt 70000) { continue }
                $in = Make $kind $n
                try { $c = [Xca]::Compress([uint16]($format -bor $engine), $in) }
                catch { throw "format $format engine $engine $kind $n : $_" }
                if ($c -eq $null) { $skipped += "$format/$engine/$kind/$n "; continue }
                $lines.Add("$format $engine $n $(Hex $in) $(Hex $c)")
            }
        }
    }
}
[System.IO.File]::WriteAllLines($Out, $lines)
"wrote $($lines.Count) vectors to $Out; not compressed by Windows: $skipped"
