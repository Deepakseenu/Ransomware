/*
  yara_ransom.yar
  Enhanced YARA rules for honeypot ransomware/webshell detection.
  Place this file at ./yara/yara_ransom.yar
*/

rule ransom_note_file_name
{
  meta:
    author = "student"
    description = "Ransom note filename patterns (improved)"
    reference = "common ransom note names"
  strings:
    $r1 = /README.*DECRYPT/i
    $r2 = /HOW_TO_DECRYPT/i
    $r3 = /_READ_ME_|README-FOR-DECRYPT/i
    $r4 = /_HOW_TO_RESTORE_/i
  condition:
    any of ($r*) and filesize < 20000
}

/* Detect ransom note contents (typical phrasing, BTC, email for contact, payment instructions) */
rule ransom_note_content
{
  meta:
    author = "student"
    description = "Ransom note contents: keywords and crypto mention"
  strings:
    $s1 = "your files have been encrypted" wide ascii
    $s2 = "decrypt" wide ascii
    $s3 = "contact" wide ascii
    $s4 = "bitcoin" wide ascii
    $s5 = /[A-Za-z0-9]{26,35}([A-Za-z0-9])*/ ascii    /* possible Bitcoin-like string */
    $s6 = "send BTC" wide ascii
    $s7 = /how to (pay|contact)/i
  condition:
    (any of ($s*)) and filesize < 50000
}

/* Detect typical encrypted-file marker text or extension inside file content */
rule encrypted_extension_marker
{
  meta:
    author = "student"
    description = "Files that contain embedded markers of encrypted payloads (e.g., .enc, .locked) inside contents"
  strings:
    $e1 = ".enc" ascii
    $e2 = ".locked" ascii
    $e3 = ".crypt" ascii
    $e4 = ".crypted" ascii
  condition:
    any of ($e*) and filesize < 200000
}

/* Detect long base64-like blobs: often used to carry binary payloads or keys */
rule long_base64_blob
{
  meta:
    author = "student"
    description = "Long base64 blobs (possible embedded key/payload)"
  strings:
    $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
  condition:
    $b64 and filesize > 1024
}

/* Detect embedded RSA public keys / PEM headers in files (possible attacker public key) */
rule embedded_rsa_pubkey
{
  meta:
    author = "student"
    description = "PEM public key or RSA key block"
  strings:
    $pem_pub = "-----BEGIN PUBLIC KEY-----"
    $pem_rsa = "-----BEGIN RSA PUBLIC KEY-----"
    $pem_any = "-----BEGIN CERTIFICATE-----"
  condition:
    any of ($pem_pub, $pem_rsa, $pem_any)
}

/* Simple webshell indicators (improved) */
rule php_webshell_pattern
{
  meta:
    author = "student"
    description = "PHP webshell indicators (eval/base64/shell_exec etc.)"
  strings:
    $s1 = "eval(" ascii
    $s2 = "base64_decode(" ascii
    $s3 = "shell_exec(" ascii
    $s4 = "passthru(" ascii
    $s5 = "exec(" ascii
    $s6 = "preg_replace(" ascii
    $s7 = "assert(" ascii
    $s8 = "system(" ascii
  condition:
    (any of ($s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)) and filesize < 200000
}

/* Obfuscated/encoded PHP webshell patterns: long hex, rot13, or many chr() calls */
rule php_webshell_obfuscation
{
  meta:
    author = "student"
    description = "PHP obfuscation patterns (many chr() / hex strings)"
  strings:
    $hex_seq = /\\x[0-9A-Fa-f]{50,}/
    $chr_calls = /(chr\(|chr\s*\()/i
    $str_rot = /str_rot13\(/i
    $many_chr = /(chr\(\d+\)\s*\.\s*){10,}/
  condition:
    any of ($hex_seq, $chr_calls, $str_rot, $many_chr) and filesize < 500000
}

/* Detect likely ransomware configuration files or key blobs:
   look for strings like 'ENCRYPTION_KEY', 'KEY', or repetitive AES/ChaCha identifiers */
rule ransomware_key_artifact
{
  meta:
    author = "student"
    description = "Look for possible key artifacts or encryption markers"
  strings:
    $k1 = "ENCRYPTION_KEY" ascii
    $k2 = "PRIVATE_KEY" ascii
    $k3 = "PUBLIC_KEY" ascii
    $k4 = "KEY:" ascii
    $k5 = /AES-?256/i
    $k6 = /ChaCha20/i
  condition:
    any of ($k1,$k2,$k3,$k4,$k5,$k6)
}

/* Detect filenames often used by attackers for webshells or staging (common fragments inside file content) */
rule common_webshell_names_in_content
{
  meta:
    author = "student"
    description = "Detect content patterns referencing common upload or webshell names"
  strings:
    $u1 = "uploaded_shell" ascii
    $u2 = "webshell" ascii
    $u3 = "cmd=" ascii
    $u4 = "phpinfo(" ascii
  condition:
    any of ($u1,$u2,$u3,$u4) and filesize < 200000
}

/* Heuristic: many small files concatenated by attacker; detect repeated header lines e.g., repeated 'PK' for zips */
rule repeated_binary_marker
{
  meta:
    author = "student"
    description = "Detect repeated binary markers (e.g., many embedded ZIPs or packaged payloads)"
  strings:
    $pk = "PK\x03\x04"
  condition:
    #pk > 10
}

/*
 Notes:
 - YARA 'filesize' checks help avoid noise from very large binaries.
 - Tune `filesize` and thresholds to your environment.
 - You can add filename-aware conditions in the scanner (outside of YARA) since YARA's filename availability varies.
*/
