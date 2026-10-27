import os
import time
import requests
import base64
import yaml
import json

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_ORG = os.getenv("GITHUB_ORG", "").strip()
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# Vulnerability thresholds for PHP2Shell (CVE-2026-109618, CVE-2026-109619)
SAFE_PHP_VERSIONS = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12
}

def is_php_version_vulnerable(version_str):
    clean_v = version_str.strip().lstrip('v').split('-')[0]
    parts = clean_v.split('.')
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        return True 

    if major < 8:
        return True 
        
    version_key = (major, minor)
    if version_key in SAFE_PHP_VERSIONS:
        min_safe_patch = SAFE_PHP_VERSIONS[version_key]
        if patch < min_safe_patch:
            return True
        return False
        
    return True 

def safe_get(url):
    """Wrapper to make requests safely with timeouts, rate-limit catching, and error handling."""
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        # Check if GitHub is rate-limiting or triggering secondary limits
        if res.status_code in [403, 429]:
            print(f"\n[!] Rate limit or secondary throttle hit on {url}. Backing off for 10 seconds...")
            time.sleep(10)
            # Retry once
            res = requests.get(url, headers=HEADERS, timeout=10)
        return res
    except requests.exceptions.RequestException:
        return None

def get_file_content(repo_full_name, path):
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
    res = safe_get(url)
    if res and res.status_code == 200:
        content_b64 = res.json().get("content", "")
        try:
            return base64.b64decode(content_b64).decode('utf-8')
        except Exception:
            return None
    return None

def extract_php_versions_from_workflow(data):
    versions = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k == 'php-version':
                if isinstance(v, list):
                    versions.extend(v)
                else:
                    versions.append(v)
            else:
                versions.extend(extract_php_versions_from_workflow(v))
    elif isinstance(data, list):
        for item in data:
            versions.extend(extract_php_versions_from_workflow(item))
    return versions

def scan_github_actions(repo):
    findings = []
    url = f"https://api.github.com/repos/{repo}/contents/.github/workflows"
    res = safe_get(url)
    if res and res.status_code == 200:
        files = res.json()
        if isinstance(files, list):
            for file in files:
                if file['name'].endswith(('.yml', '.yaml')):
                    content = get_file_content(repo, file['path'])
                    if content:
                        try:
                            workflow = yaml.safe_load(content)
                            versions = extract_php_versions_from_workflow(workflow)
                            for v in versions:
                                v_str = str(v)
                                if is_php_version_vulnerable(v_str):
                                    findings.append(("vulnerable", f"Vulnerable php-version in GitHub Action `{file['name']}`: `{v_str}`"))
                                else:
                                    findings.append(("safe", f"Safe php-version in GitHub Action `{file['name']}`: `{v_str}`"))
                        except Exception:
                            pass
    return findings

def scan_repository(repo):
    findings = []
    
    # 1. Check .php-version
    content = get_file_content(repo, '.php-version')
    if content:
        ver = content.strip()
        if is_php_version_vulnerable(ver):
            findings.append(("vulnerable", f"Vulnerable version found in `.php-version`: `{ver}`"))
        else:
            findings.append(("safe", f"Safe version in `.php-version`: `{ver}`"))

    # 2. Check composer.json platform config
    composer_content = get_file_content(repo, 'composer.json')
    if composer_content:
        try:
            composer_data = json.loads(composer_content)
            php_platform = composer_data.get("config", {}).get("platform", {}).get("php")
            if php_platform:
                if is_php_version_vulnerable(php_platform):
                    findings.append(("vulnerable", f"Vulnerable platform php constraint in `composer.json`: `{php_platform}`"))
                else:
                    findings.append(("safe", f"Safe platform php constraint in `composer.json`: `{php_platform}`"))
        except:
            pass

    # 3. Check Dockerfiles
    dockerfile = get_file_content(repo, 'Dockerfile')
    if dockerfile:
        for line in dockerfile.splitlines():
            if line.strip().upper().startswith('FROM PHP'):
                findings.append(("info", f"Dockerfile base image: `{line.strip()}` (Verify patch tag manually)"))

    # 4. Check GitHub Actions Workflows
    findings.extend(scan_github_actions(repo))

    return findings

def fetch_paginated_repos(url):
    repos = []
    page = 1
    while True:
        target_url = f"{url}&page={page}&per_page=100" if "?" in url else f"{url}?page={page}&per_page=100"
        print(f"Fetching repo page {page} from {url.split('//')[1].split('/')[0]}...")
        res = safe_get(target_url)
        if not res or res.status_code != 200:
            break
        data = res.json()
        if not data or not isinstance(data, list):
            break
        repos.extend([r['full_name'] for r in data])
        if len(data) < 100:
            break
        page += 1
    return repos

def main():
    repos = []
    targets = []
    
    if GITHUB_ORG.lower() == "all":
        print("Auto-discovering organizations for the authenticated user...")
        orgs_res = safe_get("https://api.github.com/user/orgs")
        if orgs_res and orgs_res.status_code == 200:
            orgs = orgs_res.json()
            targets = [o['login'] for o in orgs]
            print(f"Found organizations: {', '.join(targets)}")
        targets.insert(0, "PERSONAL_ACCOUNT")
    elif GITHUB_ORG:
        targets = [o.strip() for o in GITHUB_ORG.split(",")]
    else:
        targets = ["PERSONAL_ACCOUNT"]

    for target in targets:
        if target == "PERSONAL_ACCOUNT":
            print("Fetching repositories for personal account...")
            repos.extend(fetch_paginated_repos("https://api.github.com/user/repos?type=owner"))
        else:
            print(f"Fetching repositories for organization: {target}...")
            repos.extend(fetch_paginated_repos(f"https://api.github.com/orgs/{target}/repos?type=all"))

    repos = list(dict.fromkeys(repos))
    print(f"\nTotal unique repositories loaded: {len(repos)}. Starting PHP2Shell scan...\n")
    
    repo_results = {}
    vulnerable_repo_count = 0
    
    for i, repo in enumerate(repos):
        print(f"Scanning [{i+1}/{len(repos)}]: {repo}")
        findings = scan_repository(repo)
        if findings:
            has_vuln = any(status == "vulnerable" for status, _ in findings)
            if has_vuln:
                vulnerable_repo_count += 1
            repo_results[repo] = (has_vuln, findings)
        
        # Polite delay to prevent triggering GitHub secondary rate limits
        time.sleep(0.2)

    target_display = GITHUB_ORG if GITHUB_ORG else "Personal User Account"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PHP2Shell Audit Report (CVE-2026-109618 / CVE-2026-109619)</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
        h1 {{ color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; margin-top: 0; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 20px; border-radius: 6px; flex: 1; text-align: center; }}
        .card h3 {{ margin: 0; font-size: 1.5em; color: #0f172a; }}
        .card p {{ margin: 5px 0 0; color: #64748b; font-size: 0.9em; }}
        .filters {{ margin: 20px 0; display: flex; gap: 10px; }}
        .filter-btn {{ background: #e2e8f0; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; color: #475569; transition: background 0.2s; }}
        .filter-btn.active {{ background: #2563eb; color: #fff; }}
        .repo-box {{ margin-bottom: 20px; border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; }}
        .repo-header {{ background: #f1f5f9; padding: 12px 15px; font-weight: bold; font-size: 1.05em; border-bottom: 1px solid #e5e7eb; color: #334155; }}
        .repo-body {{ padding: 15px; background: #fff; }}
        ul {{ margin: 0; padding-left: 20px; }}
        li {{ margin-bottom: 8px; font-size: 0.95em; }}
        .badge-vulnerable {{ background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge-safe {{ background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge-info {{ background: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        code {{ background: #f1f5f9; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PHP2Shell Audit Report (CVE-2026-109618 / CVE-2026-109619)</h1>
        <p>Target Scope: <strong>{target_display}</strong> | Scanned repositories for core PHP runtime version configurations.</p>
        
        <div class="summary">
            <div class="card">
                <h3>{len(repos)}</h3>
                <p>Repositories Scanned</p>
            </div>
            <div class="card">
                <h3>{len(repo_results)}</h3>
                <p>Repositories with Configs</p>
            </div>
            <div class="card" style="border-left: 4px solid #dc2626;">
                <h3 style="color: #dc2626;">{vulnerable_repo_count}</h3>
                <p>Vulnerable Repositories</p>
            </div>
        </div>

        <div class="filters">
            <button class="filter-btn active" onclick="filterReport('all', this)">All Repositories ({len(repo_results)})</button>
            <button class="filter-btn" onclick="filterReport('vulnerable', this)">Vulnerable Only ({vulnerable_repo_count})</button>
        </div>
        
        <div id="repo-list-container">
"""

    if repo_results:
        for repo, (has_vuln, findings) in repo_results.items():
            vuln_attr = "true" if has_vuln else "false"
            html_content += f"""
        <div class="repo-box" data-vulnerable="{vuln_attr}">
            <div class="repo-header">Repo: {repo}</div>
            <div class="repo-body">
                <ul>
"""
            for status, text in findings:
                badge = f'<span class="badge-{status}">{status.upper()}</span>'
                parts = text.split('`')
                formatted_li = ""
                for i, part in enumerate(parts):
                    if i % 2 == 1:
                        formatted_li += f"<code>{part}</code>"
                    else:
                        formatted_li += part
                
                html_content += f"                    <li>{badge} {formatted_li}</li>\n"
            html_content += """                </ul>
            </div>
        </div>
"""
    else:
        html_content += "<p>No matching configuration files or workflows were found across the scanned repositories.</p>"

    html_content += """
        </div>
    </div>

    <script>
        function filterReport(type, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const boxes = document.querySelectorAll('.repo-box');
            boxes.forEach(box => {
                if (type === 'all') {
                    box.style.display = 'block';
                } else if (type === 'vulnerable') {
                    if (box.getAttribute('data-vulnerable') === 'true') {
                        box.style.display = 'block';
                    } else {
                        box.style.display = 'none';
                    }
                }
            });
        }
    </script>
</body>
</html>
"""

    with open("php2shell_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("\nAudit complete! HTML report saved to php2shell_report.html")

if __name__ == "__main__":
    main()
