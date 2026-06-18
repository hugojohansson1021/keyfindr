import argparse
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from subdomain_spider import (
    SubdomainSpider,
    assess_finding_risk,
    certificate_dns_names,
    check_http,
    collect_rdap,
    extract_hostnames,
    finding_sort_key,
    format_terminal_finding,
    is_in_scope,
    normalize_domain,
    parse_args,
    parse_crt_sh_records,
    probe_dns,
    rdap_service_base,
    save_crt_sh_cache,
    summarize_domain_rdap,
    summarize_ip_rdap,
    wordlist_candidate,
)


class DomainTests(unittest.TestCase):
    def test_normalize_domain_accepts_url(self):
        self.assertEqual(
            normalize_domain("https://WWW.Example.com/path"),
            "www.example.com",
        )

    def test_normalize_domain_rejects_ip_address(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            normalize_domain("192.0.2.10")

    def test_scope_requires_dns_label_boundary(self):
        self.assertTrue(is_in_scope("api.example.com", "example.com"))
        self.assertFalse(is_in_scope("notexample.com", "example.com"))

    def test_extract_hostnames_filters_other_domains(self):
        text = """
        https://api.example.com/v1
        CDN.EXAMPLE.COM
        https://outside.test/
        https://api.example.com.evil.test/
        wildcard: *.stage.example.com
        """
        self.assertEqual(
            extract_hostnames(text, "example.com"),
            {
                "api.example.com",
                "cdn.example.com",
                "stage.example.com",
            },
        )

    def test_wordlist_candidate_supports_labels_and_fqdns(self):
        self.assertEqual(
            wordlist_candidate("api", "example.com"),
            "api.example.com",
        )
        self.assertEqual(
            wordlist_candidate("dev.example.com", "example.com"),
            "dev.example.com",
        )
        self.assertEqual(
            wordlist_candidate("api.dev", "example.com"),
            "api.dev.example.com",
        )
        self.assertIsNone(
            wordlist_candidate("not_valid", "example.com"),
        )

    def test_crt_sh_is_enabled_by_default(self):
        with patch.object(
            sys,
            "argv",
            ["subdomain_spider.py", "--domain", "example.com"],
        ):
            self.assertTrue(parse_args().crt_sh)

    def test_crt_sh_can_be_disabled(self):
        with patch.object(
            sys,
            "argv",
            [
                "subdomain_spider.py",
                "--domain",
                "example.com",
                "--no-crt-sh",
            ],
        ):
            self.assertFalse(parse_args().crt_sh)


class CertificateTests(unittest.TestCase):
    def test_certificate_dns_names_prefers_subject_alt_names(self):
        certificate = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "api.example.com"),
                ("IP Address", "192.0.2.1"),
            ),
            "subject": ((("commonName", "ignored.example.com"),),),
        }
        self.assertEqual(
            certificate_dns_names(certificate),
            {"example.com", "api.example.com"},
        )

    def test_certificate_dns_names_falls_back_to_common_name(self):
        certificate = {
            "subject": ((("commonName", "legacy.example.com"),),),
        }
        self.assertEqual(
            certificate_dns_names(certificate),
            {"legacy.example.com"},
        )

    @patch("subdomain_spider.fetch_certificate")
    def test_certificate_discovery_follows_new_in_scope_hosts(self, fetch):
        certificates = {
            "example.com": {
                "subjectAltName": (
                    ("DNS", "api.example.com"),
                    ("DNS", "*.example.com"),
                    ("DNS", "outside.test"),
                )
            },
            "api.example.com": {
                "subjectAltName": (("DNS", "dev.example.com"),)
            },
            "dev.example.com": {"subjectAltName": ()},
        }
        fetch.side_effect = lambda hostname, port, timeout: certificates[hostname]
        spider = SubdomainSpider(
            domain="example.com",
            timeout=1,
            threads=2,
            tls_port=443,
            max_pages=5,
            max_cert_hosts=10,
            insecure=False,
        )

        spider.inspect_certificates(["example.com"])

        self.assertIn("api.example.com", spider.findings)
        self.assertIn("dev.example.com", spider.findings)
        self.assertNotIn("outside.test", spider.findings)
        self.assertEqual(spider.wildcard_certificates, {"*.example.com"})


class CertificateTransparencyTests(unittest.TestCase):
    def test_parse_crt_sh_records_filters_deduplicates_and_limits(self):
        certificates = [
            {
                "id": 1,
                "issuer_name": "Issuer A",
                "name_value": "example.com\napi.example.com\n*.stage.example.com",
                "not_before": "2026-01-01",
                "not_after": "2026-04-01",
            },
            {
                "id": 2,
                "issuer_name": "Issuer B",
                "name_value": "api.example.com\noutside.test",
            },
            {
                "id": 3,
                "issuer_name": "Issuer C",
                "name_value": "www.example.com",
            },
        ]

        records = parse_crt_sh_records(certificates, "example.com", 2)

        self.assertEqual(
            [record["hostname"] for record in records],
            ["api.example.com", "stage.example.com"],
        )
        self.assertEqual(records[0]["certificate_id"], 1)

    @patch("subdomain_spider.requests.get")
    def test_crt_sh_discovery_adds_metadata(self, get):
        response = get.return_value
        response.json.return_value = [
            {
                "id": 123,
                "issuer_name": "Test CA",
                "name_value": "api.example.com",
                "not_before": "2026-01-01",
                "not_after": "2026-04-01",
            }
        ]
        spider = SubdomainSpider(
            domain="example.com",
            timeout=1,
            threads=2,
            tls_port=443,
            max_pages=5,
            max_cert_hosts=10,
            insecure=False,
        )

        result = spider.discover_crt_sh(max_hosts=50, refresh=True)

        self.assertEqual(result["discovered_count"], 1)
        finding = spider.findings["api.example.com"]
        self.assertIn("certificate_transparency:crt.sh", finding.sources)
        self.assertEqual(
            finding.certificate_transparency["certificate_id"],
            123,
        )

    @patch("subdomain_spider.time.sleep")
    @patch("subdomain_spider.requests.get")
    def test_crt_sh_retries_transient_http_errors(self, get, sleep):
        failed_response = unittest.mock.Mock()
        failed_response.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("502 Bad Gateway")
        )
        successful_response = unittest.mock.Mock()
        successful_response.json.return_value = [
            {
                "id": 123,
                "issuer_name": "Test CA",
                "name_value": "api.example.com",
            }
        ]
        get.side_effect = [failed_response, successful_response]
        spider = SubdomainSpider(
            domain="example.com",
            timeout=1,
            threads=2,
            tls_port=443,
            max_pages=5,
            max_cert_hosts=10,
            insecure=False,
        )

        result = spider.discover_crt_sh(max_hosts=50, refresh=True)

        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["discovered_count"], 1)
        sleep.assert_called_once_with(1)

    @patch("subdomain_spider.time.sleep")
    @patch("subdomain_spider.requests.get")
    def test_crt_sh_uses_cache_after_repeated_failures(self, get, sleep):
        get.side_effect = requests.exceptions.HTTPError("502 Bad Gateway")
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "subdomain_spider.CRT_SH_CACHE_DIRECTORY",
                Path(directory),
            ):
                save_crt_sh_cache(
                    "example.com",
                    [
                        {
                            "hostname": "cached.example.com",
                            "issuer": "Cached CA",
                            "certificate_id": 123,
                        }
                    ],
                )
                spider = SubdomainSpider(
                    domain="example.com",
                    timeout=1,
                    threads=2,
                    tls_port=443,
                    max_pages=5,
                    max_cert_hosts=10,
                    insecure=False,
                )

                result = spider.discover_crt_sh(
                    max_hosts=50,
                    refresh=True,
                )

        self.assertTrue(result["cache_used"])
        self.assertEqual(result["attempts"], 2)
        self.assertIn("cached.example.com", spider.findings)
        self.assertFalse(spider.errors)
        self.assertEqual(sleep.call_count, 1)

    @patch("subdomain_spider.requests.get")
    def test_crt_sh_uses_fresh_cache_without_network(self, get):
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "subdomain_spider.CRT_SH_CACHE_DIRECTORY",
                Path(directory),
            ):
                save_crt_sh_cache(
                    "example.com",
                    [
                        {
                            "hostname": "cached.example.com",
                            "issuer": "Cached CA",
                            "certificate_id": 123,
                        }
                    ],
                )
                spider = SubdomainSpider(
                    domain="example.com",
                    timeout=1,
                    threads=2,
                    tls_port=443,
                    max_pages=5,
                    max_cert_hosts=10,
                    insecure=False,
                )

                result = spider.discover_crt_sh(max_hosts=50)

        get.assert_not_called()
        self.assertTrue(result["cache_used"])
        self.assertEqual(result["attempts"], 0)
        self.assertIn("cached.example.com", spider.findings)


class DnsTests(unittest.TestCase):
    @patch("subdomain_spider.resolve_hostname")
    def test_bruteforce_filters_exact_wildcard_answers(self, resolve):
        def answers(hostname):
            if hostname == "api.example.com":
                return {"192.0.2.20"}
            return {"192.0.2.10"}

        resolve.side_effect = answers
        spider = SubdomainSpider(
            domain="example.com",
            timeout=1,
            threads=2,
            tls_port=443,
            max_pages=5,
            max_cert_hosts=10,
            insecure=False,
        )

        result = spider.brute_force_dns(
            ["api", "random"],
            include_wildcard_matches=False,
        )

        self.assertIn("api.example.com", spider.findings)
        self.assertNotIn("random.example.com", spider.findings)
        self.assertEqual(
            result["skipped_wildcard_matches"],
            ["random.example.com"],
        )

    @patch("subdomain_spider.resolve_ptr")
    @patch("subdomain_spider.query_dns_record")
    def test_probe_dns_builds_cname_chain_and_ptr(self, query, ptr):
        def answer(hostname, record_type, timeout):
            del timeout
            values = {
                ("api.example.com", "A"): ["192.0.2.10"],
                ("api.example.com", "CNAME"): ["target.example.net"],
                ("target.example.net", "CNAME"): [],
                ("target.example.net", "A"): ["192.0.2.10"],
            }.get((hostname, record_type), [])
            return {
                "status": "ok" if values else "no_answer",
                "ttl": 300 if values else None,
                "values": values,
            }

        query.side_effect = answer
        ptr.return_value = ["host.provider.example"]

        result = probe_dns("api.example.com", timeout=1)

        self.assertEqual(result["status"], "resolved")
        self.assertEqual(
            result["cname_chain"],
            [
                {
                    "name": "api.example.com",
                    "target": "target.example.net",
                    "ttl": 300,
                }
            ],
        )
        self.assertEqual(
            result["ptr"]["192.0.2.10"],
            ["host.provider.example"],
        )

    @patch("subdomain_spider.query_dns_record")
    def test_probe_dns_stops_after_nxdomain(self, query):
        query.return_value = {
            "status": "nxdomain",
            "ttl": None,
            "values": [],
        }

        result = probe_dns("missing.example.com", timeout=1)

        self.assertEqual(result["status"], "nxdomain")
        query.assert_called_once_with("missing.example.com", "A", 1)
        self.assertEqual(
            result["records"]["TXT"]["status"],
            "skipped_nxdomain",
        )


class HttpProbeTests(unittest.TestCase):
    @patch("subdomain_spider.requests.get")
    def test_http_probe_blocks_out_of_scope_redirect(self, get):
        response = get.return_value
        response.status_code = 302
        response.headers = {"Location": "https://outside.test/"}

        result = check_http(
            "api.example.com",
            "example.com",
            timeout=1,
            insecure=False,
        )

        self.assertTrue(result["reachable"])
        self.assertEqual(
            result["blocked_redirect"],
            "https://outside.test/",
        )

    @patch("subdomain_spider.requests.get")
    def test_http_probe_extracts_title_and_security_headers(self, get):
        response = get.return_value
        response.status_code = 200
        response.headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Server": "example-server",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        response.encoding = "utf-8"
        response.raw.read.return_value = (
            b"<html><head><title>Admin Portal</title></head></html>"
        )

        result = check_http(
            "admin.example.com",
            "example.com",
            timeout=1,
            insecure=False,
        )

        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["title"], "Admin Portal")
        self.assertEqual(result["server"], "example-server")
        self.assertIn(
            "Content-Security-Policy",
            result["missing_security_headers"],
        )

    @patch("subdomain_spider.check_http")
    def test_http_enrichment_skips_unresolved_hosts(self, check):
        spider = SubdomainSpider(
            domain="example.com",
            timeout=1,
            threads=2,
            tls_port=443,
            max_pages=5,
            max_cert_hosts=10,
            insecure=False,
        )
        spider.add_finding("old.example.com", "test")

        spider.probe_http_findings()

        check.assert_not_called()
        self.assertEqual(
            spider.findings["old.example.com"].http_probe["skipped_reason"],
            "dns_unresolved",
        )


class RiskTests(unittest.TestCase):
    def test_flags_dangling_provider_cname_as_takeover_risk(self):
        finding = {
            "hostname": "app.example.com",
            "certificate_transparency": {"certificate_id": 1},
            "dns": {
                "status": "dangling_cname",
                "final_cname_target": "unused.github.io",
            },
            "http_probe": {
                "reachable": False,
                "takeover_fingerprints": [],
            },
            "tls": None,
        }

        risk = assess_finding_risk(finding)

        self.assertEqual(risk["level"], "HIGH")
        self.assertTrue(risk["potential_takeover"])

    def test_flags_expired_unverified_tls(self):
        finding = {
            "hostname": "secure.example.com",
            "certificate_transparency": None,
            "dns": {"status": "resolved"},
            "http_probe": {
                "reachable": True,
                "https": True,
                "missing_security_headers": [],
                "takeover_fingerprints": [],
            },
            "tls": {
                "available": True,
                "expired": True,
                "not_after": "2025-01-01T00:00:00+00:00",
                "days_remaining": -10,
                "verified": False,
                "verification_error": "certificate expired",
                "self_signed": False,
            },
        }

        risk = assess_finding_risk(finding)

        self.assertEqual(risk["level"], "HIGH")
        self.assertGreaterEqual(len(risk["findings"]), 2)


class RdapTests(unittest.TestCase):
    def test_summarizes_domain_and_network_rdap(self):
        domain = summarize_domain_rdap(
            {
                "handle": "EXAMPLE",
                "ldhName": "example.com",
                "status": ["active"],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
                "secureDNS": {"delegationSigned": True},
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2000-01-01T00:00:00Z",
                    }
                ],
                "entities": [],
            }
        )
        network = summarize_ip_rdap(
            {
                "handle": "NET-192-0-2-0-1",
                "name": "TEST-NET",
                "startAddress": "192.0.2.0",
                "endAddress": "192.0.2.255",
                "country": "US",
                "entities": [],
            },
            "192.0.2.10",
        )

        self.assertTrue(domain["dnssec"])
        self.assertEqual(domain["nameservers"], ["ns1.example.com"])
        self.assertEqual(network["name"], "TEST-NET")
        self.assertEqual(network["queried_ips"], ["192.0.2.10"])

    @patch("subdomain_spider.load_rdap_bootstrap")
    def test_selects_authoritative_rdap_service(self, bootstrap):
        bootstrap.return_value = (
            {
                "services": [
                    [["192.0.2.0/24"], ["https://rdap.example.test/"]]
                ]
            },
            None,
        )

        base, error = rdap_service_base("ip", "192.0.2.10", timeout=1)

        self.assertIsNone(error)
        self.assertEqual(base, "https://rdap.example.test/")

    def test_attaches_rdap_network_to_matching_finding(self):
        spider = SubdomainSpider(
            domain="example.com",
            timeout=1,
            threads=2,
            tls_port=443,
            max_pages=5,
            max_cert_hosts=10,
            insecure=False,
        )
        spider.add_finding(
            "api.example.com",
            "test",
            addresses={"192.0.2.10"},
        )

        spider.attach_rdap_networks(
            {
                "ip_networks": [
                    {
                        "queried_ips": ["192.0.2.10"],
                        "handle": "NET-TEST",
                        "name": "TEST-NET",
                        "owner": "Example Hosting",
                        "country": "SE",
                        "start_address": "192.0.2.0",
                        "end_address": "192.0.2.255",
                    }
                ]
            }
        )

        self.assertEqual(
            spider.findings["api.example.com"].rdap_networks[0]["owner"],
            "Example Hosting",
        )

    @patch("subdomain_spider.query_rdap")
    def test_collect_rdap_skips_non_global_addresses(self, query):
        query.return_value = (
            {
                "handle": "EXAMPLE",
                "ldhName": "example.com",
                "entities": [],
            },
            None,
        )

        result = collect_rdap(
            "example.com",
            ["127.0.0.1", "10.0.0.1"],
            timeout=1,
        )

        self.assertEqual(
            result["skipped_non_global_ips"],
            ["10.0.0.1", "127.0.0.1"],
        )
        query.assert_called_once_with("domain", "example.com", 1)


class TerminalOutputTests(unittest.TestCase):
    def test_formats_reachable_finding(self):
        finding = {
            "hostname": "api.example.com",
            "addresses": ["192.0.2.10", "2001:db8::10"],
            "http_probe": {
                "reachable": True,
                "http_status": 200,
            },
        }

        self.assertEqual(
            format_terminal_finding(finding),
            "\n".join(
                (
                    "Subdomän: api.example.com",
                    "Status:   200",
                    "IP:       192.0.2.10, 2001:db8::10",
                    "CNAME:    -",
                    "PTR:      -",
                    "Titel:    -",
                    "Server:   -",
                    "Headers:  Ej kontrollerade",
                    "TLS:      Ej tillgänglig",
                    "Nätägare: -",
                    "Risk:     INFO",
                    "Orsak:    -",
                )
            ),
        )

    def test_sorts_200_then_other_statuses_then_unreachable(self):
        findings = [
            {
                "hostname": "offline.example.com",
                "http_probe": {"reachable": False, "http_status": None},
            },
            {
                "hostname": "missing.example.com",
                "http_probe": {"reachable": True, "http_status": 404},
            },
            {
                "hostname": "z.example.com",
                "http_probe": {"reachable": True, "http_status": 200},
            },
            {
                "hostname": "a.example.com",
                "http_probe": {"reachable": True, "http_status": 200},
            },
        ]

        self.assertEqual(
            [
                finding["hostname"]
                for finding in sorted(findings, key=finding_sort_key)
            ],
            [
                "a.example.com",
                "z.example.com",
                "missing.example.com",
                "offline.example.com",
            ],
        )

    def test_formats_unreachable_unresolved_finding(self):
        finding = {
            "hostname": "old.example.com",
            "addresses": [],
            "http_probe": {
                "reachable": False,
                "http_status": None,
            },
        }

        self.assertEqual(
            format_terminal_finding(finding),
            "\n".join(
                (
                    "Subdomän: old.example.com",
                    "Status:   Ej nåbar",
                    "IP:       Ej upplöst",
                    "CNAME:    -",
                    "PTR:      -",
                    "Titel:    -",
                    "Server:   -",
                    "Headers:  Ej kontrollerade",
                    "TLS:      Ej tillgänglig",
                    "Nätägare: -",
                    "Risk:     INFO",
                    "Orsak:    -",
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
