# cth
**Hunting Custom-Built Malware Specifically Designed to Target Your Organization**

Generates custom yara file that helps in hunting malware binaries that are specifically written to target your organization. Use the generated yara file with any yara interpretor.

cth_corp_fingerprint.yaml: Modify this file to specify your organization specific details

**USAGE:**

cth_generate_yara.py [-h] [--loose] [--output OUTPUT] [--include-behavioral-rules] yaml_file

**positional arguments:**
  yaml_file             Path to YAML fingerprint file

**options:**

  -h, --help
  
  show this help message and exit
  
  --loose
  
  Disable strict mode (default is strict)
  
  --output OUTPUT
  
  Output filename (.yar)
  
  --include-behavioral-rules
  
  Include behavioral YARA rules

**Example 1:** Strict mode by default to reduce false positives

python ./cth_generate_yara.py cth_corp_fingerprint.yaml

**Example 2:** Use included behavioral analysis for common malware TTP 

python ./cth_generate_yara.py cth_corp_fingerprint.yaml --include-behavioral-rules

**Example 3:** Loose mode that does not consider context strings malware

python ./cth_generate_yara.py cth_corp_fingerprint.yaml --loose
