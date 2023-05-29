import json
import pathlib
import subprocess
from typing import Final
from urllib.parse import urlparse
import re

from init_args_for_starter import args

ROOT_PATH: Final = pathlib.Path(__file__).parent


def start_scan(target: str, file_storage: pathlib.Path):
    print("start program")
    app = subprocess.Popen(
        [
            'python3',
            str(ROOT_PATH / "raccoon_src" / "main.py"),
            '--full-scan',
            '--vulners-nmap-scan',
            '--follow-redirects',
            "-o",
            file_storage.absolute(),
            target,
        ],
        cwd=ROOT_PATH,
    )
    app.communicate()
    print("end program")


def text_cleaner(text: str) -> str:
    pattern_to_remove: list[str] = [
        r"\\u001b.*?\\u001b",
        r"\t\u001b\[\d+;\d+m.*?\[0;0m",
    ]

    clear_text = ""

    for pattern in pattern_to_remove:
        clear_text = re.sub(pattern, "", text)

    return clear_text


def main(target: str, file_storage: pathlib.Path):
    start_scan(target=target, file_storage=file_storage)
    print("start format data")
    parsed_url = urlparse(target)
    domain = parsed_url.netloc

    path_to_results: pathlib.Path = file_storage.joinpath(domain)
    all_files_content_as_dict: list[dict] = []

    final_result = {"FUZZING_RESULTS": [], "NMAP_RESULTS": [], "TLS_RESULTS": [], "WAF_RESULTS": {},
                    "SUBDOMAINS_RESULTS": [], "ROBOTS_TXT_RESULTS": [], "WEB_SCAN_RESULTS": {}}

    for file in path_to_results.iterdir():
        if file.suffix != ".txt":
            continue

        scan_name = file.stem
        file_content = file.read_text()

        # FIX CONTENT FORMAT

        if scan_name == 'url_fuzz':
            lines = file_content.split('\n')
            FUZZING_RESULTS = []

            for line in lines:
                match = re.search(r"\bhttps?://\S+", line)
                if match:
                    url = match.group()
                    FUZZING_RESULTS.append({"url": url})

            final_result["FUZZING_RESULTS"] = FUZZING_RESULTS

        elif scan_name == 'nmap_vulners_scan':
            lines = file_content.split('\n')
            NMAP_RESULTS = []

            header_index = next((i for i, line in enumerate(lines) if re.search(r"PORT\s+STATE\s+SERVICE\s+VERSION",
                                                                                line)), None)

            if header_index is not None:
                pattern = r"(\d+/tcp)\s*(\w*)\s*(\S*)\s*(.*)"

                vulners_index = next((i for i, line in enumerate(lines) if "vulners:" in line), None)
                service_detection_index = next(
                    (i for i, line in enumerate(lines) if "Service detection performed" in line), None)

                for line in lines[header_index + 1:]:
                    if line.strip():
                        match = re.match(pattern, line)
                        if match:
                            port = match.group(1)
                            state = match.group(2) if match.group(2) else None
                            service = match.group(3).strip() if match.group(3) else None
                            version = match.group(4).strip() if match.group(4) else None
                            result_dict = {
                                "PORT": port,
                                "STATE": state,
                                "SERVICE": service,
                                "VERSION": version
                            }

                            vulners_dict = {"vulners": {"list_url_vulns": []}}

                            if vulners_index is not None and vulners_index < service_detection_index:
                                vulners_urls = []
                                for line in lines[vulners_index + 1:service_detection_index]:
                                    if "http://" in line or "https://" in line:
                                        url = re.search(r"(https?://\S+)", line).group(1)
                                        vulners_urls.append({"url_vuln": url})

                                vulners_dict = {"vulners": {"list_url_vulns": vulners_urls}}

                            result_dict.update(vulners_dict)
                            NMAP_RESULTS.append(result_dict)

            final_result["NMAP_RESULTS"] = NMAP_RESULTS

        elif scan_name == 'tls_report':
            lines = file_content.split('\n')

            certificate_index = None
            for i, line in enumerate(lines):
                if "SNI Data:" in line:
                    certificate_index = i
                    break

            if certificate_index is not None:
                lines = lines[:certificate_index]

            cleaned_lines = [re.sub(r"\|\s*", "", line) for line in lines]

            TLS_RESULTS = []

            if any("Could not obtain any TLS data from target" in line for line in cleaned_lines):
                final_result['TLS_RESULTS'] = []
            else:
                tls_objects = [line for line in cleaned_lines if line.startswith('TLSv') or line.startswith('SSLv')]

                # Extract data between "TLSv" objects
                for i, tls_obj in enumerate(tls_objects):
                    supported_cipher = {}
                    supported_cipher["supported_cipher"] = tls_obj.replace(":", "").strip()

                    if i < len(tls_objects) - 1:
                        start_index = cleaned_lines.index(tls_obj) + 1
                        end_index = cleaned_lines.index(tls_objects[i + 1])
                        ciphers = cleaned_lines[start_index:end_index]
                    else:
                        start_index = cleaned_lines.index(tls_obj) + 1
                        ciphers = cleaned_lines[start_index:]

                    ciphers = [cipher for cipher in ciphers if cipher.startswith("TLS")]
                    supported_cipher["ciphers"] = [{"cipher": cipher} for cipher in ciphers]
                    warnings = []
                    warnings_start_index = cleaned_lines.index(tls_obj) + 1

                    warnings_end_index = len(cleaned_lines)
                    if i < len(tls_objects) - 1:
                        warnings_end_index = cleaned_lines.index(tls_objects[i + 1])

                    for j in range(warnings_start_index, warnings_end_index):
                        if cleaned_lines[j].startswith("warnings:"):
                            warnings = [{"warning": line} for line in cleaned_lines[j + 1:warnings_end_index] if
                                        line.strip() and not line.startswith("-------------")
                                        and not line.startswith("_") and not line.startswith("_  least strength")]
                            break

                    supported_cipher["warnings"] = warnings
                    TLS_RESULTS.append(supported_cipher)

            final_result["TLS_RESULTS"] = TLS_RESULTS

        elif scan_name == 'WAF':
            lines = file_content.split('\n')
            detected_waf = False
            waf_name = None

            for line in lines:
                if "Detected WAF presence in web application" in line:
                    detected_waf = True
                    waf_name = line.split(":")[1].strip()
                    break

            WAF_RESULTS = {"WAF": waf_name, "Detected": detected_waf} if detected_waf \
                else {"WAF": None, "Detected": False}

            final_result["WAF_RESULTS"] = WAF_RESULTS

        elif scan_name == 'web_scan':
            lines = file_content.split('\n')

            WEB_SCAN_RESULTS = {}
            # Check if "Found robots.txt" is present
            found_robots_txt = any("Found robots.txt" in line for line in lines)
            WEB_SCAN_RESULTS["Found_robots_txt"] = found_robots_txt

            # Check if "Web server detected" is present and extract the value
            web_server_line = next((line for line in lines if "Web server detected" in line), None)
            if web_server_line:
                _, web_server = web_server_line.split(":")
                WEB_SCAN_RESULTS["Web_server_detected"] = web_server.strip()
            else:
                WEB_SCAN_RESULTS["Web_server_detected"] = None

            powered_by_header_line = next((line for line in lines if "X-Powered-By header detected" in line), None)
            if powered_by_header_line:
                _, powered_by_header = powered_by_header_line.split(":")
                WEB_SCAN_RESULTS["X-Powered-By_header_detected"] = powered_by_header.strip()
            else:
                WEB_SCAN_RESULTS["X-Powered-By_header_detected"] = False

            # Check if "X-Frame-Options header not detected" is present
            x_frame_options_not_detected = any("X-Frame-Options header not detected" in line for line in lines)
            if x_frame_options_not_detected:
                WEB_SCAN_RESULTS["X-Frame-Options_header_detected"] = False
                WEB_SCAN_RESULTS["X-Frame-Options_Info"] = "Might be vulnerable to clickjacking"
            else:
                WEB_SCAN_RESULTS["X-Frame-Options_header_detected"] = True
                WEB_SCAN_RESULTS["X-Frame-Options_Info"] = "not vulnerable to clickjacking"

            # Check if "Cookie:" is present and extract the value
            result_list = []
            for line in lines:
                if line.startswith("Cookie:"):
                    cookie_info = line.split(":")[1].strip().split("-")
                    cookie = cookie_info[0].strip() if cookie_info else None
                    cookie_info = cookie_info[1].strip() if len(cookie_info) > 1 else None
                    result_dict = {
                        "Cookie": cookie,
                        "Cookie_Info": cookie_info
                    }
                    result_list.append(result_dict)

            WEB_SCAN_RESULTS['Cookies'] = result_list

            # Check for Fuzzable URLs
            for i, line in enumerate(lines):
                if "fuzzable URLs discovered" in line:
                    urls = []
                    for url_line in lines[i + 1:]:
                        match = re.search(r"\bhttps?://\S+", url_line)
                        if match:
                            url = match.group()
                            urls.append({"url": url})
                    WEB_SCAN_RESULTS["Fuzzable_URLs_discovered"] = urls
                    break
            else:
                WEB_SCAN_RESULTS["Fuzzable_URLs_discovered"] = []

            final_result["WEB_SCAN_RESULTS"] = WEB_SCAN_RESULTS

        elif scan_name == 'robots':
            lines = file_content.split('\n')
            ROBOTS_TXT_RESULTS = []

            for line in lines:
                if "Disallow:" in line:
                    path = line.split("Disallow:")[1].strip()
                    result_dict = {"status": "Disallow", "path": path}
                    ROBOTS_TXT_RESULTS.append(result_dict)
                elif "Allow:" in line:
                    path = line.split("Allow:")[1].strip()
                    result_dict = {"status": "Allow", "path": path}
                    ROBOTS_TXT_RESULTS.append(result_dict)

            final_result["ROBOTS_TXT_RESULTS"] = ROBOTS_TXT_RESULTS

        elif scan_name == 'subdomain_fuzz':
            lines = file_content.split('\n')
            SUBDOMAINS_RESULTS = []

            for line in lines:
                match = re.search(r"\bhttps?://\S+", line)
                if match:
                    url = match.group()
                    SUBDOMAINS_RESULTS.append({"url": url})

            final_result["SUBDOMAINS_RESULTS"] = SUBDOMAINS_RESULTS

        clear_text_from_file = text_cleaner(text=file_content)
        clear_text_as_lines = clear_text_from_file.splitlines()

        all_files_content_as_dict.append(
            {
                scan_name: clear_text_as_lines
            }
        )

        # remove parsed file
        file.unlink(missing_ok=True)


    # path_to_result_file_1: pathlib.Path = ROOT_PATH.joinpath("final.json")
    # path_to_result_file_1.write_text(json.dumps(all_files_content_as_dict))

    path_to_result_file: pathlib.Path = ROOT_PATH.joinpath("result.json")
    path_to_result_file.write_text(json.dumps(final_result))


if __name__ == "__main__":
    storage_dir = args.storage or "result"
    storage_path = ROOT_PATH.joinpath(storage_dir)
    input_target = args.target
    main(
        target=input_target,
        file_storage=storage_path,
    )
