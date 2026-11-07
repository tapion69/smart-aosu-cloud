"""Constants for the unofficial AOSU Cloud integration."""
from pathlib import Path
DOMAIN = "smart_aosu_cloud"
VERSION = "0.8.10"
CONF_EMAIL = "email"
CONF_PASSWORD = "password"
PROFILE_PATH = Path("/config/smart_aosu_cloud/profile.json")
APK_PATH = Path("/config/smart_aosu_cloud/aosu_vendor_app.apk")
# Polling for 4 devices is batched into ONE read-only getList call.
# Values below are bounded, because this is an undocumented cloud endpoint.
CONF_SCAN_INTERVAL = "scan_interval_seconds"
DEFAULT_SCAN_INTERVAL = 120  # 2 minutes; reduced from 600 seconds
ALLOWED_SCAN_INTERVALS = (60, 120, 300, 600, 900)
UPDATE_SECONDS = DEFAULT_SCAN_INTERVAL  # backwards compatible constant
