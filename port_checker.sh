#!/bin/bash
# Local security report: listeners, sharing, firewall, and a few Mac settings.
# Listeners owned by root can stay hidden unless this script is run with sudo.
# --email sends the full report once a day when the assessment finds a problem.

if [[ "${1:-}" == "--email" ]]; then
  config_dir="$HOME/.config/port-checker"
  stamp_file="$config_dir/last-email-date"
  log_file="$config_dir/email.log"
  env_file="$HOME/.config/two-day-screener/env"
  mail_to="evan.wright16@gmail.com"
  today=$(date +%Y-%m-%d)
  mkdir -p "$config_dir"

  email_log() {
    printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$1" >> "$log_file"
  }

  report=$("$0" 2>&1) || true
  printf '%s\n' "$report"

  if grep -q "No issues found in this report." <<< "$report"; then
    email_log "No issues. Not sending."
    exit 0
  fi
  if ! grep -q "CAUTION: Potential security concerns" <<< "$report"; then
    email_log "Report did not finish. Not sending."
    exit 1
  fi
  if [[ -f "$stamp_file" && "$(tr -d '[:space:]' < "$stamp_file")" == "$today" ]]; then
    email_log "Already sent the $today report."
    exit 0
  fi

  password=""
  if [[ -f "$env_file" ]]; then
    password=$(awk -F= '/^GMAIL_APP_PASSWORD=/ {sub(/^[^=]*=/,""); print; exit}' "$env_file")
    password=$(printf '%s' "$password" | tr -d '[:space:]"'"'"'')
  fi
  if [[ -z "$password" ]]; then
    email_log "Gmail app password missing. Not sending."
    exit 1
  fi

  if ! printf '%s\n' "$report" | GMAIL_APP_PASSWORD="$password" MAIL_TO="$mail_to" REPORT_DATE="$today" \
    /Library/Frameworks/Python.framework/Versions/3.14/bin/python3 -c '
import os
import sys
import smtplib
from email.message import EmailMessage

message = EmailMessage()
message["From"] = os.environ["MAIL_TO"]
message["To"] = os.environ["MAIL_TO"]
message["Subject"] = "Port checker found a problem " + os.environ["REPORT_DATE"]
message.set_content(sys.stdin.read())
with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as smtp:
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(os.environ["MAIL_TO"], os.environ["GMAIL_APP_PASSWORD"])
    smtp.send_message(message)
'
  then
    email_log "Email failed."
    exit 1
  fi

  printf '%s\n' "$today" > "$stamp_file"
  email_log "Sent the $today report to $mail_to"
  exit 0
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/port-checker.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

has_nonapple_network_visible="no"
has_remote_access_tools="no"
has_pending_updates="no"
has_java_network_listeners="no"
remote_login_enabled="Off"
screen_sharing_enabled="Off"
file_sharing_enabled="Off"
remote_management_enabled="Off"
firewall_problem="no"
stealth_off="no"
filevault_off="no"
gatekeeper_off="no"
sip_off="no"
screen_lock_problem="no"
guest_on="no"
screen_lock_detail=""

service_state() {
  local label="$1"
  local output
  output=$(launchctl print "system/${label}" 2>&1) || true
  if grep -q 'Could not find service' <<< "$output"; then
    echo "Off"
  elif grep -qE 'state = |active =' <<< "$output"; then
    echo "On"
  else
    echo "Unknown"
  fi
}

is_apple_process() {
  case "$1" in
    rapportd|ControlCenter|mDNSResponder|configd|apsd|trustd|softwareupdated|powerd|UserEventAgent|opendirectoryd|syslogd|sharingd|screensharingd|remoted|identityservicesd|AirPlayXPCHelper|bluetoothd|WiFiAgent|symptomsd|netbiosd|socketfilterfw|launchd|kernelmanagerd)
      return 0
      ;;
  esac
  return 1
}

is_java_process() {
  local name
  name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  [[ "$name" == *java* ]]
}

parse_endpoint() {
  local endpoint="$1"
  if [[ "$endpoint" == \[* ]]; then
    bind_addr="${endpoint#\[}"
    bind_addr="${bind_addr%%\]*}"
    port="${endpoint##*:}"
  else
    bind_addr="${endpoint%:*}"
    port="${endpoint##*:}"
  fi
}

scope_for_bind() {
  case "$1" in
    127.0.0.1|::1|localhost)
      echo "local-only"
      ;;
    "*"|"0.0.0.0"|"::"|"::0")
      echo "network-visible"
      ;;
    "")
      echo "unknown"
      ;;
    *)
      echo "network-visible"
      ;;
  esac
}

describe_port() {
  local process="$1"
  local port="$2"
  local bind="$3"

  case "$process" in
    rapportd)
      echo "Apple Continuity / device proximity service"
      return
      ;;
    ControlCenter)
      if [[ "$port" == "5000" || "$port" == "7000" ]]; then
        echo "AirPlay Receiver (Control Center)"
      else
        echo "Control Center service"
      fi
      return
      ;;
    Cursor)
      echo "Cursor editor internal service"
      return
      ;;
  esac

  if is_java_process "$process"; then
    echo "Java-based app or development tool"
    return
  fi

  case "$port" in
    22)
      if [[ "$bind" == "127.0.0.1" || "$bind" == "::1" ]]; then
        echo "SSH (Remote Login) restricted to this Mac"
      else
        echo "SSH (Remote Login) reachable from the network"
      fi
      ;;
    80)
      echo "HTTP web server"
      ;;
    443)
      echo "HTTPS web server"
      ;;
    445)
      echo "SMB file sharing"
      ;;
    548)
      echo "AFP file sharing"
      ;;
    5900)
      echo "VNC screen sharing"
      ;;
    *)
      if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 49152 )); then
        echo "Listening service on a high port"
      else
        echo "Listening service; check if you recognize this application"
      fi
      ;;
  esac
}

classify_expectation() {
  local process="$1"
  local port="$2"
  local bind="$3"
  local scope
  scope=$(scope_for_bind "$bind")

  if is_apple_process "$process"; then
    echo "✅ Expected (Apple system service)"
    return
  fi

  if [[ "$scope" == "local-only" ]]; then
    echo "✅ Expected (local-only listener; only this Mac can connect)"
    return
  fi

  if [[ "$port" == "22" ]]; then
    echo "🟡 Depends (SSH is reachable on the network; expected only if you use Remote Login)"
    return
  fi

  if is_java_process "$process"; then
    echo "🔴 Review (Java is reachable from other devices on your network)"
    return
  fi

  echo "🔴 Review (reachable from other devices on your network; confirm you recognize and need this app)"
}

echo "======================================== PORT WATCHDOG REPORT ========================================"
echo
echo "A listener on * or on this Mac's network address is reachable by other devices on the same network."
echo "The public internet reaches it only if the router forwards that port, or if the app connects outward on its own."
echo "Listeners owned by root can be missing from this report unless it is run with sudo."
echo

listeners_file="$tmp_dir/listeners"
lsof -nP -iTCP -sTCP:LISTEN +c 0 2>/dev/null | sed '1d' > "$listeners_file"

echo "🔍 Listening Ports:"
local_only_count=0
network_visible_count=0

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  process=$(awk '{print $1}' <<< "$line")
  endpoint=$(sed -E 's/.* TCP (.+) \(LISTEN\).*/\1/' <<< "$line")
  if [[ "$endpoint" == "$line" ]]; then
    echo "$line"
    echo "    → Could not read the address for this listener"
    continue
  fi
  parse_endpoint "$endpoint"
  scope=$(scope_for_bind "$bind_addr")

  echo "$line"
  echo "    → $(describe_port "$process" "$port" "$bind_addr")"
  echo "    → $(classify_expectation "$process" "$port" "$bind_addr")"
  case "$scope" in
    local-only)
      local_only_count=$((local_only_count + 1))
      echo "    → Scope: local-only (only this Mac can connect)"
      ;;
    network-visible)
      network_visible_count=$((network_visible_count + 1))
      echo "    → Scope: network-visible (other devices on your network can connect)"
      ;;
    *)
      echo "    → Scope: unknown"
      ;;
  esac
done < "$listeners_file"

echo
echo "Listeners: ${local_only_count} local-only, ${network_visible_count} network-visible."
echo

echo "🛡️ Remote Access Services:"
remote_login_enabled=$(service_state "com.openssh.sshd")
screen_sharing_enabled=$(service_state "com.apple.screensharing")
file_sharing_enabled=$(service_state "com.apple.smbd")
remote_management_enabled=$(service_state "com.apple.RemoteDesktop.agent")

if grep -qE '(^|[[:space:]])sshd[[:space:]]' "$listeners_file"; then
  remote_login_enabled="On"
fi

echo "• Remote Login (SSH): ${remote_login_enabled}"
echo "• Screen Sharing: ${screen_sharing_enabled}"
echo "• Remote Management (Apple Remote Desktop): ${remote_management_enabled}"
echo "• File Sharing (SMB): ${file_sharing_enabled}"
if pgrep -x remoted >/dev/null 2>&1; then
  echo "ℹ️ remoted is running. That process is a normal part of macOS and is separate from Remote Login."
fi
echo

echo "🔥 Firewall Status:"
fw_cli_raw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null) || true
fw_cli_state=$(grep -oE 'State = [0-9]+' <<< "$fw_cli_raw" | awk '{print $3}')
fw_plist_state=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "")
fw_state="${fw_cli_state:-$fw_plist_state}"
stealth_raw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null) || true
blockall_raw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null) || true

if [[ "$fw_state" == "1" || "$fw_state" == "2" ]]; then
  echo "✅ Firewall is ON (state=$fw_state)"
elif [[ "$fw_state" == "0" ]]; then
  firewall_problem="yes"
  echo "⚠️ Firewall is OFF (state=0)"
else
  firewall_problem="yes"
  echo "⚠️ Could not determine firewall status (raw values: cli='${fw_cli_state:-n/a}' plist='${fw_plist_state:-n/a}')"
fi

if grep -Eqi 'enabled|is on' <<< "$stealth_raw"; then
  echo "✅ Firewall stealth mode is ON"
elif grep -Eqi 'disabled|is off' <<< "$stealth_raw"; then
  stealth_off="yes"
  echo "⚠️ Firewall stealth mode is OFF. Other devices can see this Mac answer on the network."
else
  echo "⚠️ Could not determine firewall stealth mode (${stealth_raw:-no output})"
fi

if grep -Eqi 'enabled|is on' <<< "$blockall_raw"; then
  echo "ℹ️ Block all incoming connections is ON"
else
  echo "ℹ️ Block all incoming connections is OFF. Leave this off unless you want to block AirPlay and other signed apps too."
fi
echo

echo "☕ Java Listening Check:"
java_file="$tmp_dir/java"
> "$java_file"
while IFS= read -r line; do
  process=$(awk '{print $1}' <<< "$line")
  if is_java_process "$process"; then
    echo "$line" >> "$java_file"
  fi
done < "$listeners_file"

if [[ -s "$java_file" ]]; then
  while IFS= read -r line; do
    pid=$(awk '{print $2}' <<< "$line")
    endpoint=$(sed -E 's/.* TCP (.+) \(LISTEN\).*/\1/' <<< "$line")
    parse_endpoint "$endpoint"
    scope=$(scope_for_bind "$bind_addr")
    cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
    app_path=$(grep -oE '/Applications/[^ ]+\.app' <<< "$cmd" | head -n 1)
    echo "$line"
    if [[ -n "$app_path" ]]; then
      echo "    → App: $app_path"
    elif [[ -n "$cmd" ]]; then
      echo "    → Command: $cmd"
    fi
    if [[ "$scope" == "network-visible" ]]; then
      has_java_network_listeners="yes"
      echo "    → Reachable from other devices on your network"
    else
      echo "    → Local-only"
    fi
  done < "$java_file"
  if [[ "$has_java_network_listeners" == "no" ]]; then
    echo "✅ Java listeners found above are local-only."
  fi
else
  echo "✅ No Java processes listening on ports"
fi
echo

echo "🌐 Network-visible Non-Apple Services:"
nv_file="$tmp_dir/network-visible"
> "$nv_file"
while IFS= read -r line; do
  process=$(awk '{print $1}' <<< "$line")
  endpoint=$(sed -E 's/.* TCP (.+) \(LISTEN\).*/\1/' <<< "$line")
  [[ "$endpoint" == "$line" ]] && continue
  parse_endpoint "$endpoint"
  [[ "$(scope_for_bind "$bind_addr")" == "network-visible" ]] || continue
  if is_apple_process "$process"; then
    continue
  fi
  echo "$line" >> "$nv_file"
done < "$listeners_file"

if [[ -s "$nv_file" ]]; then
  has_nonapple_network_visible="yes"
  cat "$nv_file"
  echo "⚠️ Review the apps above. Other devices on your network can connect to them."
else
  echo "✅ No third-party services are listening on the network."
fi
echo

echo "🖥️ Remote Access Tools Check:"
remote_file="$tmp_dir/remote-tools"
> "$remote_file"
ps -ax -o pid=,command= > "$tmp_dir/processes"
while IFS= read -r line; do
  line="${line#"${line%%[![:space:]]*}"}"
  [[ -z "$line" ]] && continue
  pid=${line%%[[:space:]]*}
  cmd=${line#"$pid"}
  cmd="${cmd#"${cmd%%[![:space:]]*}"}"
  [[ "$cmd" == *CoreParsec.framework* ]] && continue
  base=$(basename "${cmd%% *}")
  desc=""
  case "$base" in
    TeamViewer|TeamViewer_Service|teamviewerd)
      desc="TeamViewer can control this Mac when a session is signed in."
      ;;
    AnyDesk|anydesk)
      desc="AnyDesk can reach this Mac over the internet for remote control."
      ;;
    rustdesk|RustDesk)
      desc="RustDesk can reach this Mac through a public or self-hosted relay."
      ;;
    LogMeIn|logmein)
      desc="LogMeIn can keep a persistent remote-control connection to this Mac."
      ;;
    Splashtop|SRService|splashtop)
      desc="Splashtop can access this Mac from other devices."
      ;;
    Parsec|parsecd)
      if [[ "$cmd" == *Parsec.app* || "$base" == "Parsec" ]]; then
        desc="Parsec can stream and control this Mac's desktop."
      fi
      ;;
    remoting_me2me_host|chromoting)
      desc="Chrome Remote Desktop can share this Mac through a Google account."
      ;;
  esac
  if [[ -n "$desc" ]]; then
    printf '%s\n%s\n' "$pid $cmd" "    → $desc" >> "$remote_file"
  fi
done < "$tmp_dir/processes"

if [[ -s "$remote_file" ]]; then
  has_remote_access_tools="yes"
  echo "⚠️ These remote-access processes are running:"
  cat "$remote_file"
else
  echo "✅ No common remote-access tools are running."
fi
echo

echo "🧩 Startup & Background Items:"
echo "These start at login or in the background. They are listed so you can recognize them."
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  if [[ ! -d "$dir" ]]; then
    continue
  fi
  count=0
  echo "$dir:"
  for item_path in "$dir"/*; do
    [[ -e "$item_path" ]] || continue
    item=$(basename "$item_path")
    count=$((count + 1))
    if [[ "$item" == com.apple.* ]]; then
      kind="Apple/system"
    else
      kind="Third-party"
    fi
    echo "  - $item ($kind)"
  done
  if (( count == 0 )); then
    echo "  (none)"
  fi
  echo
done

echo "🔐 Mac Protection Settings:"

filevault_raw=$(fdesetup status 2>&1) || true
if grep -q 'FileVault is On' <<< "$filevault_raw"; then
  echo "✅ FileVault is ON"
elif grep -q 'FileVault is Off' <<< "$filevault_raw"; then
  filevault_off="yes"
  echo "⚠️ FileVault is OFF. The disk is readable if the Mac is stolen."
else
  filevault_off="yes"
  echo "⚠️ Could not determine FileVault status (${filevault_raw:-no output})"
fi

gatekeeper_raw=$(spctl --status 2>&1) || true
if grep -q 'assessments enabled' <<< "$gatekeeper_raw"; then
  echo "✅ Gatekeeper is ON"
elif grep -q 'assessments disabled' <<< "$gatekeeper_raw"; then
  gatekeeper_off="yes"
  echo "⚠️ Gatekeeper is OFF. The Mac will open apps that have not been checked."
else
  gatekeeper_off="yes"
  echo "⚠️ Could not determine Gatekeeper status (${gatekeeper_raw:-no output})"
fi

sip_raw=$(csrutil status 2>&1) || true
if grep -q 'enabled' <<< "$sip_raw"; then
  echo "✅ System Integrity Protection is ON"
elif grep -q 'disabled' <<< "$sip_raw"; then
  sip_off="yes"
  echo "⚠️ System Integrity Protection is OFF"
else
  sip_off="yes"
  echo "⚠️ Could not determine System Integrity Protection status (${sip_raw:-no output})"
fi

screen_lock_raw=$(sysadminctl -screenLock status 2>&1) || true
if grep -q 'immediate' <<< "$screen_lock_raw"; then
  echo "✅ A password is required immediately after the screen sleeps"
elif grep -qE 'delay is [0-9]+ seconds' <<< "$screen_lock_raw"; then
  screen_lock_seconds=$(grep -oE 'delay is [0-9]+ seconds' <<< "$screen_lock_raw" | awk '{print $3}')
  screen_lock_minutes=$((screen_lock_seconds / 60))
  screen_lock_problem="yes"
  screen_lock_detail="${screen_lock_minutes} minutes (${screen_lock_seconds} seconds)"
  echo "⚠️ A password is required ${screen_lock_detail} after the screen sleeps."
elif grep -Eqi 'off|disabled' <<< "$screen_lock_raw"; then
  screen_lock_problem="yes"
  screen_lock_detail="off"
  echo "⚠️ A password is not required after the screen sleeps."
else
  screen_lock_problem="yes"
  screen_lock_detail="unknown"
  echo "⚠️ Could not determine the lock-screen password (${screen_lock_raw:-no output})"
fi

guest_raw=$(sysadminctl -guestAccount status 2>&1) || true
guest_pref=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "")
if grep -q 'disabled' <<< "$guest_raw" || [[ "$guest_pref" == "0" ]]; then
  echo "✅ Guest account is OFF"
elif grep -q 'enabled' <<< "$guest_raw" || [[ "$guest_pref" == "1" ]]; then
  guest_on="yes"
  echo "⚠️ Guest account is ON"
else
  echo "⚠️ Could not determine guest account status (${guest_raw:-no output})"
fi
echo

echo "🌐 Browser & Extensions Reminder:"
echo "• Review installed browser extensions and remove ones you do not recognize."
echo "• Keep two-factor authentication on the account that syncs the browser."
echo

echo "🧱 macOS Update Status:"
if updates_output=$(softwareupdate -l 2>/dev/null); then
  if grep -q "No new software available." <<< "$updates_output"; then
    echo "✅ No pending macOS software updates reported."
  elif grep -qE '^[[:space:]]*\* Label:' <<< "$updates_output"; then
    has_pending_updates="yes"
    echo "⚠️ macOS reports available updates:"
    echo "$updates_output" | grep -E '^[[:space:]]*\* Label:|^[[:space:]]*Title:'
  else
    echo "ℹ️ softwareupdate did not clearly list pending updates."
  fi
else
  echo "⚠️ Could not determine update status (softwareupdate failed)."
fi
echo "ℹ️ App Store apps, including Xcode, update separately in the App Store."
echo

echo "===== END OF REPORT ====="
echo
echo "🔒 OVERALL SAFETY ASSESSMENT:"

concerns="no"
if [[ "$remote_login_enabled" == "On" || "$screen_sharing_enabled" == "On" || "$remote_management_enabled" == "On" || "$has_java_network_listeners" == "yes" || "$firewall_problem" == "yes" || "$stealth_off" == "yes" || "$has_nonapple_network_visible" == "yes" || "$has_remote_access_tools" == "yes" || "$has_pending_updates" == "yes" || "$filevault_off" == "yes" || "$gatekeeper_off" == "yes" || "$sip_off" == "yes" || "$screen_lock_problem" == "yes" || "$guest_on" == "yes" ]]; then
  concerns="yes"
fi

if [[ "$concerns" == "yes" ]]; then
  echo "⚠️  CAUTION: Potential security concerns detected."
  echo
  echo "🔧 RECOMMENDED ACTIONS:"

  if [[ "$remote_login_enabled" == "On" ]]; then
    echo "• Turn off Remote Login unless you use SSH: System Settings → General → Sharing → Remote Login."
  fi
  if [[ "$screen_sharing_enabled" == "On" ]]; then
    echo "• Turn off Screen Sharing unless you need it: System Settings → General → Sharing → Screen Sharing."
  fi
  if [[ "$remote_management_enabled" == "On" ]]; then
    echo "• Turn off Remote Management unless you use Apple Remote Desktop: System Settings → General → Sharing."
  fi
  if [[ "$has_java_network_listeners" == "yes" ]]; then
    echo "• A Java process is reachable from the network. Confirm you recognize it and bind it to 127.0.0.1 if it only needs this Mac."
  fi
  if [[ "$firewall_problem" == "yes" ]]; then
    echo "• Turn on the macOS firewall: System Settings → Network → Firewall."
  fi
  if [[ "$stealth_off" == "yes" ]]; then
    echo "• Turn on firewall stealth mode: System Settings → Network → Firewall → Options → Enable stealth mode."
  fi
  if [[ "$has_nonapple_network_visible" == "yes" ]]; then
    echo "• Review the network-visible apps above and quit or restrict any you do not need."
  fi
  if [[ "$has_remote_access_tools" == "yes" ]]; then
    echo "• Keep only remote-access tools you trust, and turn on their account passwords and two-factor authentication."
  fi
  if [[ "$filevault_off" == "yes" ]]; then
    echo "• Turn on FileVault: System Settings → Privacy & Security → FileVault."
  fi
  if [[ "$gatekeeper_off" == "yes" ]]; then
    echo "• Turn Gatekeeper back on: sudo spctl --master-enable"
  fi
  if [[ "$sip_off" == "yes" ]]; then
    echo "• Turn System Integrity Protection back on from Recovery."
  fi
  if [[ "$screen_lock_problem" == "yes" ]]; then
    if [[ "$screen_lock_detail" == "off" ]]; then
      echo "• Require a password when the screen sleeps: System Settings → Lock Screen."
    elif [[ "$screen_lock_detail" == "unknown" ]]; then
      echo "• Check Lock Screen and require a password immediately after the display sleeps."
    else
      echo "• The lock-screen password waits ${screen_lock_detail}. Set it to immediately: System Settings → Lock Screen."
    fi
  fi
  if [[ "$guest_on" == "yes" ]]; then
    echo "• Turn off the guest account: System Settings → Users & Groups."
  fi
  if [[ "$has_pending_updates" == "yes" ]]; then
    echo "• Install the pending macOS updates, and update App Store apps separately."
  fi
else
  echo "✅  No issues found in this report."
fi

echo
echo "Report complete."
exit 0
