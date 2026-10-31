# core/report_generator.py
import os
import json
import datetime
import logging
from typing import Dict, Any, Optional
from jinja2 import Template, Environment, FileSystemLoader, BaseLoader

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generator laporan HTML/PDF untuk hasil scan dan offensive operation.
    Mendukung output dalam format JSON terstruktur dan HTML yang dapat dibaca manusia.
    """

    def __init__(self, output_dir: str = "output", template_dir: str = None):
        self.output_dir = output_dir
        self.template_dir = template_dir or os.path.join(os.path.dirname(__file__), "templates")
        
        # Pastikan direktori output ada
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup Jinja2 Environment
        if os.path.exists(self.template_dir):
            self.jinja_env = Environment(loader=FileSystemLoader(self.template_dir))
        else:
            # Fallback jika template tidak ada, kita akan generate HTML manual di render_html()
            self.jinja_env = Environment(loader=BaseLoader())
            
        logger.info(f"ReportGenerator initialized. Output dir: {self.output_dir}")

    def _generate_filename(self, prefix: str, ext: str) -> str:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.{ext}"

    def generate_json_report(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Menghasilkan laporan dalam format JSON.
        """
        if not filename:
            filename = self._generate_filename("scan_report", "json")
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, default=str, ensure_ascii=False)
            logger.info(f"JSON report generated successfully: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise

    def generate_html_report(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """
        Menghasilkan laporan HTML yang kaya visualisasi.
        """
        if not filename:
            filename = self._generate_filename("scan_report", "html")
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Struktur data default jika kosong
        if not data:
            data = {"title": "BSSN Scan Report", "sections": []}

        # Coba gunakan template Jinja2 jika tersedia
        template_name = "report_template.html"
        template = None
        try:
            template = self.jinja_env.get_template(template_name)
        except Exception:
            template = None
        
        if template:
            html_content = template.render(**data)
        else:
            # Fallback: Generate HTML manual sederhana namun profesional
            html_content = self._generate_html_manual(data)

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report generated successfully: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def _generate_html_manual(self, data: Dict[str, Any]) -> str:
        """
        Generate HTML string secara manual jika template tidak ditemukan.
        """
        title = data.get('title', 'BSSN Security Report')
        sections = data.get('sections', [])
        
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='id'>",
            "<head>",
            "    <meta charset='UTF-8'>",
            "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"    <title>{title}</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }",
            "        .container { max-width: 1200px; margin: auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }",
            "        h1 { color: #333; border-bottom: 2px solid #0056b3; padding-bottom: 10px; }",
            "        h2 { color: #0056b3; margin-top: 30px; }",
            "        table { width: 100%; border-collapse: collapse; margin-top: 10px; }",
            "        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }",
            "        th { background-color: #0056b3; color: white; }",
            "        tr:nth-child(even) { background-color: #f2f2f2; }",
            "        .critical { color: red; font-weight: bold; }",
            "        .warning { color: orange; font-weight: bold; }",
            "        .info { color: blue; }",
            "        .footer { margin-top: 40px; font-size: 0.8em; color: #777; text-align: center; }",
            "    </style>",
            "</head>",
            "<body>",
            "    <div class='container'>",
            f"        <h1>{title}</h1>",
            f"        <p><strong>Tanggal Laporan:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        ]

        for section in sections:
            sec_title = section.get('title', 'No Title')
            sec_content = section.get('content', '')
            sec_table = section.get('table_data', None)
            
            html_parts.append(f"<h2>{sec_title}</h2>")
            
            if isinstance(sec_content, list):
                html_parts.append("<ul>")
                for item in sec_content:
                    html_parts.append(f"<li>{item}</li>")
                html_parts.append("</ul>")
            elif isinstance(sec_content, str):
                html_parts.append(f"<p>{sec_content}</p>")
            
            if sec_table:
                html_parts.append("<table>")
                if sec_table.get('headers'):
                    html_parts.append("<thead><tr>")
                    for header in sec_table['headers']:
                        html_parts.append(f"<th>{header}</th>")
                    html_parts.append("</tr></thead>")
                
                html_parts.append("<tbody>")
                for row in sec_table.get('rows', []):
                    html_parts.append("<tr>")
                    for cell in row:
                        html_parts.append(f"<td>{cell}</td>")
                    html_parts.append("</tr>")
                html_parts.append("</tbody>")
                html_parts.append("</table>")

        html_parts.extend([
            "    </div>",
            "    <div class='footer'>",
            "        Generated by BSSN Pentest Toolkit | NoTrack AI Model",
            "    </div>",
            "</body>",
            "</html>"
        ])

        return "\n".join(html_parts)

    def generate_offensive_report(self, exploit_results: List[Dict], target_info: Dict, summary: Dict) -> Dict:
        """
        Menggabungkan hasil offensive ke dalam struktur laporan khusus.
        """
        return {
            "type": "offensive",
            "target": target_info,
            "exploits_executed": len(exploit_results),
            "success_rate": len([e for e in exploit_results if e.get('status') == 'success']) / max(len(exploit_results), 1),
            "details": exploit_results,
            "summary": summary,
            "generated_at": datetime.datetime.now().isoformat()
        }

    def combine_and_export(self, scan_data: Dict, offensive_data: Dict, 
                           scan_filename: str = None, offensive_filename: str = None):
        """
        Menggabungkan hasil scan dan offensive menjadi satu laporan komprehensif.
        """
        combined = {
            "scan_results": scan_data,
            "offensive_results": offensive_data,
            "combined_metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "framework": "BSSN Pentest Toolkit"
            }
        }
        
        # Export JSON
        if scan_filename:
            self.generate_json_report(combined, scan_filename)
        else:
            self.generate_json_report(combined)
            
        # Export HTML
        html_data = self._prepare_html_data(combined)
        self.generate_html_report(html_data)
        
        return combined

    def _prepare_html_data(self, combined_data: Dict) -> Dict:
        """
        Mempersiapkan data untuk template HTML.
        """
        sections = []
        
        # Tambahkan bagian Summary
        sections.append({
            "title": "Executive Summary",
            "content": f"Laporan ini mencakup hasil scan kerentanan dan eksploitasi pada target BSSN.",
            "table_data": {
                "headers": ["Metric", "Value"],
                "rows": [
                    ["Total CVE Ditemukan", len(combined_data.get('scan_results', {}).get('cves', []))],
                    ["Exploit Berhasil", len([e for e in combined_data.get('offensive_results', {}).get('exploits', []) if e.get('status') == 'success'])]
                ]
            }
        })
        
        # Tambahkan bagian Scan Results
        cves = combined_data.get('scan_results', {}).get('cves', [])
        if cves:
            rows = [[cve.get('id'), cve.get('severity'), cve.get('description')] for cve in cves]
            sections.append({
                "title": "Vulnerability Scan Results",
                "content": "Daftar CVE yang terdeteksi melalui modul passive scanning.",
                "table_data": {
                    "headers": ["CVE ID", "Severity", "Description"],
                    "rows": rows
                }
            })
            
        # Tambahkan bagian Offensive Results
        exploits = combined_data.get('offensive_results', {}).get('exploits', [])
        if exploits:
            rows = [[exp.get('name'), exp.get('status'), exp.get('payload')] for exp in exploits]
            sections.append({
                "title": "Offensive Exploitation Results",
                "content": "Hasil eksekusi payload dari mode offensive.",
                "table_data": {
                    "headers": ["Exploit Name", "Status", "Payload/Command"],
                    "rows": rows
                }
            })
            
        return {
            "title": "BSSN Comprehensive Security Report",
            "sections": sections
        }