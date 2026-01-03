"""
Alert System for security violations
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
from datetime import datetime
from config import Config

class AlertSystem:
    """Handles security alert generation and notification"""
    
    def __init__(self):
        self.config = Config()
        self.alerts_log = self.config.get_alerts_log_path()
        
    def send_alert(self, event_type, src_path, dest_path=None, violations=None):
        """Send security alert"""
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source_path": src_path,
            "destination_path": dest_path,
            "violations": violations or [],
            "severity": self.calculate_severity(violations),
            "alert_id": self.generate_alert_id()
        }
        
        # Log alert
        self.log_alert(alert_data)
        
        # Print to console
        self.print_alert(alert_data)
        
        # Send email if configured
        if self.config.get_email_alerts_enabled():
            def __init__(self):
                self.config = Config()
                self.alerts_log = Path(self.config.get_alerts_log_path())
                self.alerts_log.parent.mkdir(parents=True, exist_ok=True)
    
    def calculate_severity(self, violations):
        """Calculate alert severity based on violations"""
        if not violations:
            return "LOW"
        
        high_severity = ["USB_TRANSFER", "NETWORK_SHARE_TRANSFER", "MASS_FILE_OPERATION"]
        medium_severity = ["RESTRICTED_FILE_TYPE", "INTEGRITY_MISMATCH"]
        
        for violation in violations:
            if violation in high_severity:
                return "HIGH"
            if violation in medium_severity:
                return "MEDIUM"
        
        return "LOW"
    
    def generate_alert_id(self):
        """Generate unique alert ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        import random
        random_num = random.randint(1000, 9999)
        return f"ALERT-{timestamp}-{random_num}"
    
    def log_alert(self, alert_data):
        """Log alert to file"""
        try:
            with open(self.alerts_log, 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
        except Exception as e:
            print(f"Error logging alert: {e}")
    
    def print_alert(self, alert_data):
        """Print alert to console with formatting"""
        severity_colors = {
            "HIGH": "\033[91m",    # Red
            "MEDIUM": "\033[93m",  # Yellow
            "LOW": "\033[94m"      # Blue
        }
        
        color = severity_colors.get(alert_data["severity"], "\033[0m")
        reset = "\033[0m"
        
        print(f"\n{color}╔{'═'*60}╗{reset}")
        print(f"{color}║ {'🚨 SECURITY ALERT':^58} ║{reset}")
        print(f"{color}╠{'═'*60}╣{reset}")
        print(f"{color}║ ID: {alert_data['alert_id']:54} ║{reset}")
        print(f"{color}║ Severity: {alert_data['severity']:48} ║{reset}")
        print(f"{color}║ Time: {alert_data['timestamp']:50} ║{reset}")
        print(f"{color}╠{'─'*60}╣{reset}")
        print(f"{color}║ Event: {alert_data['event_type']:51} ║{reset}")
        print(f"{color}║ File: {alert_data['source_path'][:52]:52} ║{reset}")
        if alert_data['destination_path']:
            print(f"{color}║ To: {alert_data['destination_path'][:54]:54} ║{reset}")
        print(f"{color}║ Violations: {reset}")
        for violation in alert_data['violations']:
            print(f"{color}║   • {violation:55} ║{reset}")
        print(f"{color}╚{'═'*60}╝{reset}\n")
    
    def send_email_alert(self, alert_data):
        """Send email alert"""
        try:
            smtp_config = self.config.get_smtp_config()
            
            msg = MIMEMultipart()
            msg['From'] = smtp_config['from_email']
            msg['To'] = smtp_config['to_email']
            msg['Subject'] = f"Security Alert: {alert_data['alert_id']}"
            
            body = f"""
            SECURITY ALERT - File Transfer Monitoring System
            
            Alert ID: {alert_data['alert_id']}
            Severity: {alert_data['severity']}
            Time: {alert_data['timestamp']}
            
            Event Details:
            --------------
            Event Type: {alert_data['event_type']}
            Source: {alert_data['source_path']}
            Destination: {alert_data['destination_path'] or 'N/A'}
            
            Violations Detected:
            """
            
            for violation in alert_data['violations']:
                body += f"  • {violation}\n"
            
            body += f"""
            
            Immediate Action Required:
            1. Review the file transfer
            2. Verify user authorization
            3. Check system logs
            
            This is an automated alert from Secure File Transfer Monitoring System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port']) as server:
                if smtp_config.get('use_tls'):
                    server.starttls()
                if smtp_config.get('username'):
                    server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)
                
            print(f"📧 Email alert sent to {smtp_config['to_email']}")
            
        except Exception as e:
            print(f"Error sending email alert: {e}")
    
    def get_recent_alerts(self, limit=10):
        """Get recent alerts from log"""
        alerts = []
        try:
            with open(self.alerts_log, 'r') as f:
                lines = f.readlines()[-limit:]
                for line in lines:
                    try:
                        alerts.append(json.loads(line.strip()))
                    except:
                        continue
        except:
            pass
        
        return alerts