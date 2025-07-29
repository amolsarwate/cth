import yaml
import argparse

def load_fingerprint(yaml_path):
    with open(yaml_path, "r") as f:
        return yaml.safe_load(f)

def escape_string(s):
    return s.replace("\\", "\\\\").replace("\"", "\\\"")

def extract_org_strings(fingerprint):
    strings = set()

    org = fingerprint.get("organization", {})
    network = fingerprint.get("network", {})
    system = fingerprint.get("system", {})
    user = fingerprint.get("user", {})
    env = fingerprint.get("environment", {})

    # Org info
    strings.add(org.get("domain_name", ""))
    strings.add(org.get("registered_organization", ""))
    strings.add(org.get("registered_owner", ""))
    if "oem" in org:
        strings.update([org["oem"].get("manufacturer", ""), org["oem"].get("support_url", "")])

    # Network
    strings.update(network.get("dns_suffixes", []))
    proxy = network.get("proxy", {})
    strings.update([proxy.get("server", ""), proxy.get("autoconfig_url", "")])
    strings.add(network.get("ad_domain", ""))

    # System
    strings.update(system.get("installed_software_keywords", []))
    strings.add(system.get("hostname_prefix", ""))
    for reg in system.get("custom_registry_keys", []):
        strings.add(reg["path"])
        if "values" in reg:
            strings.update(reg["values"].values())
    strings.update(system.get("gpo_keys", []))
    strings.update(system.get("printers", []))

    # User
    strings.add(user.get("domain_user_group", ""))
    strings.update(user.get("usernames_keywords", []))
    strings.add(user.get("sid_prefix", ""))

    # Environment
    strings.update(env.get("scheduled_tasks", []))
    if "env_vars" in env:
        strings.update(env["env_vars"].values())

    return [s for s in strings if s.strip()]

def get_context_strings():
    return [
        "reg query",
        "Get-ItemProperty",
        "nltest",
        "whoami",
        "gpresult",
        "wmic",
        "net user",
        "net group",
        "Get-WmiObject",
        "HKLM\\",
        "HKCU\\",
        "SOFTWARE\\Policies"
    ]

def generate_yara(org_strings, strict=True, rule_name="Detect_MyCorp_Targeting"):
    lines = [f"rule {rule_name}", "{", "    strings:"]
    yara_ids = []

    for i, s in enumerate(org_strings):
        yara_id = f"$org{i}"
        yara_ids.append(yara_id)
        lines.append(f'        {yara_id} = "{escape_string(s)}" nocase')

    if strict:
        lines.append("")
        context_ids = []
        for i, cs in enumerate(get_context_strings()):
            cid = f"$ctx{i}"
            context_ids.append(cid)
            lines.append(f'        {cid} = "{escape_string(cs)}" nocase')
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        any of ({', '.join(yara_ids)}) and any of ({', '.join(context_ids)})")
    else:
        lines.append("")
        lines.append("    condition:")
        lines.append("        any of them")

    lines.append("}")
    return "\n".join(lines)

def get_behavioral_rules(file_path="cth_behavioral_rules.yar"):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Warning: Behavioral rules file '{file_path}' not found. Skipping behavioral rules.")
        return ""


def main():
    parser = argparse.ArgumentParser(description="Generate YARA rules from org fingerprint YAML")
    parser.add_argument("yaml_file", help="Path to YAML fingerprint file")
    parser.add_argument("--loose", action="store_true", help="Disable strict mode (default is strict)")
    parser.add_argument("--output", help="Output filename (.yar)", default=None)
    parser.add_argument("--include-behavioral-rules", action="store_true", help="Include behavioral YARA rules")

    args = parser.parse_args()

    fingerprint = load_fingerprint(args.yaml_file)
    org_strings = extract_org_strings(fingerprint)
    yara_rule = generate_yara(org_strings, strict=not args.loose)

    output_name = args.output or ("output_strict.yar" if not args.loose else "output_loose.yar")

    with open(output_name, "w") as f:
        f.write(yara_rule + "\n\n")
        if args.include_behavioral_rules:
            f.write(get_behavioral_rules())

    print(f"YARA rule written to {output_name}")

if __name__ == "__main__":
    main()

