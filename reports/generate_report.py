#!/usr/bin/env python3
"""
Report Generation Module
Generates HTML and CSV reports from monitoring data
"""

import json
import csv
from datetime import datetime
from pathlib import Path
import webbrowser
from logger import Logger
from alert_system import AlertSystem
import logging
import csv as _csv

# Configure module logger
logging.basicConfig(level=logging.INFO)
logger_module = logging.getLogger('report_generator')

class ReportGenerator:
    """Generates security reports from monitoring data"""
    
    def __init__(self):
        self.logger = Logger()
        self.alert = AlertSystem()

    def _read_csv_logs(self, logs_dir="logs"):
        """Read CSV companion logs from `logs_dir` and return list of log dicts.

        Handles boolean/string conversions and splits violations.
        """
        logs = []
        try:
            # Prefer CSVs in the provided logs_dir (Path or str)
            if isinstance(logs_dir, (str,)):
                logs_dir = Path(__file__).parents[1] / logs_dir

            candidates = []
            try:
                candidates.extend(sorted([p for p in Path(logs_dir).glob('*.csv')]))
            except Exception:
                pass

            # include the real-time summary CSV if present
            summary_csv = Path(__file__).parents[1] / 'reports' / 'security_summary.csv'
            if summary_csv.exists():
                candidates.append(summary_csv)

            for csv_file in candidates:
                try:
                    with open(csv_file, 'r', encoding='utf-8') as f:
                        reader = _csv.DictReader(f)
                        expected_fields = {'timestamp', 'event_type', 'source_path'}
                        if not expected_fields.intersection(set(reader.fieldnames or [])):
                            logger_module.debug(f"Skipping CSV (not logger format): {csv_file}")
                            continue

                        row_count = 0
                        for row in reader:
                            row_count += 1
                            # normalize fields (support both old and new column names)
                            sensitive_raw = row.get('is_sensitive') if row.get('is_sensitive') is not None else row.get('sensitive')
                            unauthorized_raw = row.get('is_unauthorized') if row.get('is_unauthorized') is not None else row.get('unauthorized')
                            entry = {
                                'timestamp': (row.get('timestamp') or row.get('time') or '').strip(),
                                'event_type': (row.get('event_type') or row.get('event') or 'UNKNOWN').strip(),
                                'source_path': (row.get('source_path') or row.get('source') or '').strip(),
                                'destination_path': (row.get('destination_path') or row.get('destination') or None),
                                'user': (row.get('user') or 'UNKNOWN').strip(),
                                'process': (row.get('process') or '').strip(),
                                # convert booleans (support '1','0','true','false')
                                'sensitive': str(sensitive_raw or '').strip().lower() in ('1', 'true', 'yes'),
                                'unauthorized': str(unauthorized_raw or '').strip().lower() in ('1', 'true', 'yes'),
                                'integrity_check': (row.get('integrity_check') or '').strip(),
                                'violations': [v for v in (row.get('violations') or '').split(';') if v]
                            }
                            # if severity exists in CSV, preserve it
                            if row.get('severity'):
                                entry['severity'] = (row.get('severity') or '').strip()
                            logs.append(entry)

                        logger_module.info(f"Parsed {row_count} rows from CSV: {csv_file}")
                except Exception as e:
                    logger_module.debug(f"Failed to read CSV {csv_file}: {e}")
        except Exception as e:
            logger_module.debug(f"Error scanning logs dir {logs_dir}: {e}")
        return logs

    def _merge_logs(self, json_logs, csv_logs):
        """Merge json and csv logs, deduping by (timestamp,event_type,source_path)."""
        out = []
        seen = set()
        def key_for(e):
            return (str(e.get('timestamp','')), str(e.get('event_type','')), str(e.get('source_path','')))

        for e in (json_logs or []):
            k = key_for(e)
            seen.add(k)
            out.append(e)

        for e in (csv_logs or []):
            k = key_for(e)
            if k in seen:
                continue
            out.append(e)
            seen.add(k)

        return out
    
    def generate_html_report(self, output_file="reports/security_report.html"):
        """Generate HTML security report"""
        # Get data: prefer JSON logs, fallback/merge with CSV logs
        json_logs = self.logger.get_recent_logs(limit=1000)
        csv_logs = self._read_csv_logs(logs_dir=Path(__file__).parents[1] / 'logs')
        merged_logs = self._merge_logs(json_logs, csv_logs)

        logger_module.info(f"JSON logs: {len(json_logs)} rows, CSV logs: {len(csv_logs)} rows, merged: {len(merged_logs)} rows")

        # Build summary from merged logs
        summary = self._build_summary_from_logs(merged_logs)
        # Build per-event validation info (severity classification)
        events_with_validation = []
        severity_map = {'high': 0, 'medium': 0, 'low': 0}
        for e in merged_logs:
            unauthorized = bool(e.get('unauthorized'))
            sensitive = bool(e.get('sensitive'))
            violations = e.get('violations') or []
            integrity = e.get('integrity_check') or ''

            if unauthorized or ('EXTERNAL_TRANSFER' in violations) or ('RESTRICTED_FILE_TYPE' in violations):
                severity = 'HIGH'
                severity_map['high'] += 1
            elif sensitive:
                severity = 'MEDIUM'
                severity_map['medium'] += 1
            else:
                severity = 'LOW'
                severity_map['low'] += 1

            events_with_validation.append({
                'timestamp': e.get('timestamp',''),
                'event_type': e.get('event_type',''),
                'source_path': e.get('source_path',''),
                'user': e.get('user',''),
                'sensitive': sensitive,
                'unauthorized': unauthorized,
                'violations': violations,
                'integrity_check': integrity,
                'severity': severity,
            })
        recent_alerts = self.alert.get_recent_alerts(limit=20)

        # Build SOC-style threats list (MEDIUM+ or integrity failures or unauthorized)
        threats = []
        for ev in events_with_validation:
            is_threat = (ev['severity'] in ('HIGH', 'MEDIUM')) or ev['unauthorized'] or (ev['integrity_check'] == 'FAILED')
            if is_threat:
                threats.append(ev)

        # Export threats JSON for SOC consumption / API
        try:
            out_dir = Path(__file__).parents[1] / 'reports'
            out_dir.mkdir(parents=True, exist_ok=True)
            threats_file = out_dir / 'threats.json'
            with open(threats_file, 'w', encoding='utf-8') as tf:
                json.dump({'generated': datetime.now().isoformat(), 'count': len(threats), 'threats': threats}, tf, indent=2)
        except Exception:
            logger_module.debug('Failed to write threats.json')
        # Write summary JSON for dynamic dashboard updates
        try:
            summary_json = out_dir / 'summary.json'
            with open(summary_json, 'w', encoding='utf-8') as sj:
                json.dump({
                    'generated': datetime.now().isoformat(),
                    'statistics': summary.get('statistics', {}),
                    'event_breakdown': summary.get('event_breakdown', {}),
                    'violation_summary': summary.get('violation_summary', {}),
                    'threats_count': len(threats),
                    'severity_map': severity_map
                }, sj, indent=2)
        except Exception:
            logger_module.debug('Failed to write summary.json')
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>File Transfer Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .card {{ background: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 10px 0; border-radius: 4px; }}
                .alert-high {{ border-left-color: #dc3545; background: #f8d7da; }}
                .alert-medium {{ border-left-color: #ffc107; background: #fff3cd; }}
                .alert-low {{ border-left-color: #28a745; background: #d4edda; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #2c3e50; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .stats {{ display: flex; justify-content: space-between; flex-wrap: wrap; }}
                .stat-box {{ flex: 1; min-width: 200px; background: #e9ecef; padding: 15px; margin: 10px; border-radius: 5px; text-align: center; }}
                .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
                .timestamp {{ color: #6c757d; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 Secure File Transfer Monitoring Report</h1>
                    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="stats">
                    <div class="stat-box">
                        <h3>Total Events</h3>
                            <div id="total-events" class="stat-value">{summary.get('statistics', {}).get('total_events', 0)}</div>
                    </div>
                    <div class="stat-box">
                        <h3>Unauthorized Events</h3>
                            <div id="unauth-events" class="stat-value" style="color: #dc3545;">{summary.get('statistics', {}).get('unauthorized_events', 0)}</div>
                    </div>
                    <div class="stat-box">
                        <h3>Sensitive Events</h3>
                            <div id="sensitive-events" class="stat-value" style="color: #ffc107;">{summary.get('statistics', {}).get('sensitive_events', 0)}</div>
                    </div>
                    <div class="stat-box">
                        <h3>Violation Rate</h3>
                            <div id="violation-rate" class="stat-value">{summary.get('statistics', {}).get('unauthorized_percentage', 0):.1f}%</div>
                    </div>
                </div>

                <!-- SOC Summary -->
                <div style="margin:20px 0; padding:15px; background:#eef3f8; border-radius:6px;">
                    <h2>🛡️ SOC Summary</h2>
                    <p><strong>Detected Threats:</strong> <span id="detected-threats">{len(threats)}</span></p>
                    <p><strong>High / Medium / Low:</strong> <span id="sev-high">{severity_map.get('high',0)}</span> / <span id="sev-med">{severity_map.get('medium',0)}</span> / <span id="sev-low">{severity_map.get('low',0)}</span></p>
                    <p><strong>Top Violations:</strong> {', '.join([f"{k}({v})" for k,v in summary.get('violation_summary', {}).items()]) or 'None'}</p>
                </div>
                
                <h2>📈 Event Breakdown</h2>
                <table>
                    <tr>
                        <th>Event Type</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
        """
        
        # Add event breakdown
        total = summary.get('statistics', {}).get('total_events', 1)
        for event_type, count in summary.get('event_breakdown', {}).items():
            percentage = (count / total * 100) if total > 0 else 0
            html_content += f"""
                    <tr>
                        <td>{event_type}</td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
            """
        
        html_content += """
                </table>

                <!-- RED ALERT BANNER -->
        """
        # Insert a red alert banner when there are high-severity events
        if severity_map.get('high', 0) > 0:
            html_content += f"""
                <div style=\"margin:20px 0; padding:15px; background:#f8d7da; border-left:6px solid #dc3545; border-radius:6px;\">
                    <h2 style=\"color:#721c24;\">🚨 RED ALERT: {severity_map['high']} high-severity event(s) detected</h2>
                    <p style=\"color:#721c24;\">Please review the validation details below and follow incident response procedures.</p>
                </div>
            """

        # Add Event Validation Details table
        html_content += """
                <h2>🔍 Event Validation Details</h2>
                <table>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>File</th>
                        <th>User</th>
                        <th>Sensitive</th>
                        <th>Unauthorized</th>
                        <th>Violations</th>
                        <th>Integrity</th>
                        <th>Severity</th>
                    </tr>
        """

        for ev in events_with_validation:
            viol = ', '.join(ev.get('violations') or []) or '&nbsp;'
            integrity_text = ev.get('integrity_check') or 'NOT_CHECKED'
            sev = ev.get('severity')
            sev_color = '#dc3545' if sev == 'HIGH' else ('#ffc107' if sev == 'MEDIUM' else '#28a745')
            html_content += f"""
                    <tr>
                        <td>{ev.get('timestamp')}</td>
                        <td>{ev.get('event_type')}</td>
                        <td>{ev.get('source_path')}</td>
                        <td>{ev.get('user')}</td>
                        <td>{'Yes' if ev.get('sensitive') else 'No'}</td>
                        <td>{'Yes' if ev.get('unauthorized') else 'No'}</td>
                        <td>{viol}</td>
                        <td>{integrity_text}</td>
                        <td style=\"color:{sev_color}; font-weight:bold;\">{sev}</td>
                    </tr>
            """

        html_content += """
            </table>

            <h2>🚨 Recent Security Alerts</h2>
        """
        
        # Add alerts
        for alert in recent_alerts:
            severity_class = f"alert-{alert.get('severity', 'low').lower()}"
            html_content += f"""
                <div class="card {severity_class}">
                    <h3>{alert.get('alert_id', 'Unknown')} - {alert.get('severity', 'UNKNOWN')}</h3>
                    <p><strong>Time:</strong> {alert.get('timestamp', '')}</p>
                    <p><strong>Event:</strong> {alert.get('event_type', '')}</p>
                    <p><strong>File:</strong> {alert.get('source_path', '')}</p>
                    <p><strong>Violations:</strong> {', '.join(alert.get('violations', []))}</p>
                </div>
            """
        
        html_content += """
                <h2>👤 User Activity Summary</h2>
                <table>
                    <tr>
                        <th>Username</th>
                        <th>File Events</th>
                        <th>Last Activity</th>
                    </tr>
        """
        
        # Add user activity
        for user, count in summary.get('user_activity', {}).items():
            html_content += f"""
                    <tr>
                        <td>{user}</td>
                        <td>{count}</td>
                        <td>Recent</td>
                    </tr>
            """
        
        html_content += """
                </table>
                
                <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                    <h3>🔒 Security Recommendations</h3>
                    <ul>
                        <li>Review all HIGH severity alerts immediately</li>
                        <li>Check USB transfer policies for compliance</li>
                        <li>Verify user permissions on sensitive directories</li>
                        <li>Schedule regular integrity checks on critical files</li>
                        <li>Consider implementing additional DLP solutions</li>
                    </ul>
                </div>
                
                <footer style="margin-top: 30px; text-align: center; color: #6c757d; font-size: 0.9em;">
                    <p>Generated by Secure File Transfer Monitoring System v1.0</p>
                    <p>This report contains sensitive security information. Handle with care.</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        # Write HTML file
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            # append a small JS snippet to fetch summary.json periodically
            refresh_js = '''
            <script>
            async function refreshSummary(){
                try{
                    const res = await fetch('summary.json', {cache: 'no-store'});
                    if(!res.ok) return;
                    const data = await res.json();
                    const stats = data.statistics || {};
                    document.getElementById('total-events').innerText = stats.total_events || 0;
                    document.getElementById('unauth-events').innerText = stats.unauthorized_events || 0;
                    document.getElementById('sensitive-events').innerText = stats.sensitive_events || 0;
                    document.getElementById('violation-rate').innerText = (stats.unauthorized_percentage||0).toFixed(1) + '%';
                    document.getElementById('detected-threats').innerText = data.threats_count || 0;
                    const sev = data.severity_map || {};
                    document.getElementById('sev-high').innerText = sev.high || 0;
                    document.getElementById('sev-med').innerText = sev.medium || 0;
                    document.getElementById('sev-low').innerText = sev.low || 0;
                }catch(e){console.debug('refreshSummary',e)}
            }
            // initial load and periodic refresh
            refreshSummary();
            setInterval(refreshSummary, 5000);
            </script>
            '''
            f.write(html_content)
            f.write(refresh_js)
        
        print(f"✅ Report generated: {output_path}")
        
        # Open in browser
        webbrowser.open(f'file://{output_path.resolve()}')
    
    def generate_csv_report(self, output_file="reports/security_summary.csv"):
        """Generate CSV summary report"""
        # Avoid overwriting the real-time per-event feed at reports/security_summary.csv
        if str(output_file).endswith('reports/security_summary.csv'):
            output_file = 'reports/security_summary_report.csv'

        json_logs = self.logger.get_recent_logs(limit=1000)
        csv_logs = self._read_csv_logs(logs_dir=Path(__file__).parents[1] / 'logs')
        merged_logs = self._merge_logs(json_logs, csv_logs)
        summary = self._build_summary_from_logs(merged_logs)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Security Report Summary', 'Value'])
            writer.writerow(['Report Time', datetime.now().isoformat()])
            writer.writerow([])
            
            # Write statistics
            writer.writerow(['Statistics', ''])
            for key, value in summary.get('statistics', {}).items():
                writer.writerow([key, value])
            
            writer.writerow([])
            
            # Write event breakdown
            writer.writerow(['Event Breakdown', 'Count'])
            for event_type, count in summary.get('event_breakdown', {}).items():
                writer.writerow([event_type, count])
        
        print(f"✅ CSV report generated: {output_file}")

    def _build_summary_from_logs(self, logs):
        """Convert a list of log entries into the same summary dict used previously."""
        if not logs:
            return {"statistics": {}, "event_breakdown": {}, "user_activity": {}, "report_time": datetime.now().isoformat()}

        total_events = len(logs)
        unauthorized_events = sum(1 for log in logs if bool(log.get('unauthorized')))
        sensitive_events = sum(1 for log in logs if bool(log.get('sensitive')))

        event_types = {}
        users = {}
        violations = {}
        for log in logs:
            event_type = log.get('event_type') or 'UNKNOWN'
            event_types[event_type] = event_types.get(event_type, 0) + 1

            user = log.get('user') or 'UNKNOWN'
            users[user] = users.get(user, 0) + 1

            for v in log.get('violations') or []:
                violations[v] = violations.get(v, 0) + 1

        return {
            "report_time": datetime.now().isoformat(),
            "statistics": {
                "total_events": int(total_events),
                "unauthorized_events": int(unauthorized_events),
                "sensitive_events": int(sensitive_events),
                "unauthorized_percentage": (unauthorized_events / total_events * 100) if total_events > 0 else 0
            },
            "event_breakdown": event_types,
            "user_activity": users,
            "violation_summary": violations
        }

def main():
    """Main function for report generation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate security reports')
    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    parser.add_argument('--csv', action='store_true', help='Generate CSV report')
    parser.add_argument('--all', action='store_true', help='Generate all reports')
    parser.add_argument('--output', type=str, help='Output directory')
    
    args = parser.parse_args()
    
    generator = ReportGenerator()
    
    if args.all or (not args.html and not args.csv):
        # Default: generate both
        generator.generate_html_report()
        generator.generate_csv_report()
    else:
        if args.html:
            generator.generate_html_report()
        if args.csv:
            generator.generate_csv_report()

if __name__ == "__main__":
    main()
def main():
    """Main function for report generation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate security reports')
    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    parser.add_argument('--csv', action='store_true', help='Generate CSV report')
    parser.add_argument('--all', action='store_true', help='Generate all reports')
    parser.add_argument('--output', type=str, help='Output directory')
    
    args = parser.parse_args()
    
    generator = ReportGenerator()
    
    if args.all or (not args.html and not args.csv):
        # Default: generate both
        generator.generate_html_report()
        generator.generate_csv_report()
    else:
        if args.html:
            generator.generate_html_report()
        if args.csv:
            generator.generate_csv_report()

if __name__ == "__main__":
    main()