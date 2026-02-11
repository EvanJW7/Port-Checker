#!/bin/bash

describe_port() {
  local process="$1"
  local port="$2"
  local bind="$3"

  case "${process}:${port}" in
    rapportd:*)
      echo "Apple Continuity / device proximity service"
      ;;
    java:*|java-arm:*)
      echo "Java-based app or development tool listening locally"
      ;;
    Cursor:*)
      echo "Cursor editor internal service"
      ;;
    *:22)
      if [[ "$bind" == "127.0.0.1" ]]; then
        echo "SSH (Remote Login) restricted to localhost"
      else
        echo "SSH (Remote Login) exposed on the network"
      fi
      ;;
    *:80)
      echo "HTTP web server"
      ;;
    *:443)
      echo "HTTPS web server"
      ;;
    *:17500|*:17600|*:17603)
      echo "Dropbox LAN sync"
      ;;
    *)
      if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 49152 )); then
        echo "Ephemeral high-number port, often used for temporary or local services"
      else
        echo "Listening service; check if you recognize this application"
      fi
      ;;
  esac
}

echo "===== PORT WATCHDOG REPORT ====="
echo

# 1. Show all listening ports
echo "🔍 Listening Ports:"
local_only_count=0
network_visible_count=0

lsof -i -P -n | grep LISTEN | while IFS= read -r line; do
  process=$(awk '{print $1}' <<< "$line")
  address_port=$(grep -oE '[0-9a-fA-F\.:]+:[0-9]+' <<< "$line" | tail -n 1)
  bind_addr="${address_port%:*}"
  port="${address_port##*:}"

  scope="unknown"
  if [[ "$bind_addr" == "127.0.0.1" || "$bind_addr" == "::1" ]]; then
    scope="local-only"
  elif [[ "$bind_addr" == "0.0.0.0" || "$bind_addr" == "*" || "$bind_addr" == "::" ]]; then
    scope="network-visible"
  fi

  description=$(describe_port "$process" "$port" "$bind_addr")
  echo "$line"
  echo "    → $description"

  case "$scope" in
    local-only)
      echo "    → Scope: local-only (only this Mac can connect)"
      ;;
    network-visible)
      echo "    → Scope: network-visible (other devices on your network can connect)"
      ;;
  esac
done
echo


# 2. Check if Remote Management (remoted) is running
echo "🛡️ Remote Management Check:"
if pgrep remoted >/dev/null; then
  # Check if Remote Login is actually enabled
  remote_login_status=$(sudo systemsetup -getremotelogin 2>/dev/null | grep -o "On\|Off")
  if [[ "$remote_login_status" == "On" ]]; then
    echo "⚠️ 'remoted' is running AND Remote Login is ENABLED — Security risk!"
  else
    echo "ℹ️ 'remoted' is running but Remote Login is DISABLED — Normal system behavior"
  fi
else
  echo "✅ 'remoted' not running"
fi
echo

# 3. Check for Dropbox LAN sync (multiple known ports)
echo "📦 Dropbox LAN Sync Check:"
dropbox_ports="17500 17600 17603"
dropbox_found=false
for port in $dropbox_ports; do
  if lsof -iTCP:$port -sTCP:LISTEN >/dev/null; then
    echo "⚠️ Dropbox LAN sync port ($port) is open"
    dropbox_found=true
  fi
done

# Also check for any Dropbox processes with listening ports
dropbox_listeners=$(lsof -i -P -n | grep LISTEN | grep -i dropbox)
if [[ -n "$dropbox_listeners" ]]; then
  echo "⚠️ Dropbox processes with listening ports found:"
  echo "$dropbox_listeners"
  dropbox_found=true
fi

if [[ "$dropbox_found" == false ]]; then
  echo "✅ Dropbox LAN sync ports not open"
fi
echo

# 4. Check key macOS sharing services
echo "📡 Sharing Services:"
remote_login_pref=$(sudo systemsetup -getremotelogin 2>/dev/null | grep -o "On\|Off")
screen_sharing_pref=$(launchctl print system/com.apple.screensharing 2>/dev/null | grep -q "enabled = 1" && echo "On" || echo "Off")
file_sharing_pref=$(sharing -l 2>/dev/null | grep -q "File Sharing" && echo "On" || echo "Off")

echo "• Remote Login (SSH): ${remote_login_pref:-Unknown}"
echo "• Screen Sharing (VNC): ${screen_sharing_pref:-Unknown}"
echo "• File Sharing (SMB/AFP): ${file_sharing_pref:-Unknown}"
echo

# 5. Check if macOS firewall is enabled
echo "🔥 Firewall Status:"

# Try socketfilterfw first (more authoritative), fall back to defaults
fw_cli_raw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
fw_cli_state=$(grep -oE 'State = [0-9]+' <<< "$fw_cli_raw" 2>/dev/null | awk '{print $3}')
fw_plist_state=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "")

fw_state="${fw_cli_state:-$fw_plist_state}"

if [[ "$fw_state" == "1" || "$fw_state" == "2" ]]; then
  echo "✅ Firewall is ON (state=$fw_state)"
elif [[ "$fw_state" == "0" ]]; then
  echo "⚠️ Firewall is OFF (state=0)"
else
  echo "⚠️ Could not determine firewall status (raw values: cli='${fw_cli_state:-n/a}' plist='${fw_plist_state:-n/a}')"
fi
echo

# 6. Check for active Java processes with listening ports
echo "☕ Java Listening Check:"
lsof -i -P -n | grep LISTEN | grep java > /tmp/ports_watchdog_java_listeners.$$ 2>/dev/null

if [[ -s /tmp/ports_watchdog_java_listeners.$$ ]]; then
  echo "⚠️ Java process is listening on:"
  while IFS= read -r line; do
    pid=$(awk '{print $2}' <<< "$line")
    # Get full command for the PID
    cmd=$(ps -p "$pid" -o command= 2>/dev/null)
    # Try to extract an app bundle path if present
    app_path=$(grep -oE '/Applications/[^ ]+\.app' <<< "$cmd" | head -n 1)

    echo "$line"
    if [[ -n "$app_path" ]]; then
      echo "    → App: $app_path"
    elif [[ -n "$cmd" ]]; then
      echo "    → Command: $cmd"
    else
      echo "    → Origin: Unknown (process may have exited)"
    fi
  done < /tmp/ports_watchdog_java_listeners.$$
else
  echo "✅ No Java processes listening on ports"
fi
rm -f /tmp/ports_watchdog_java_listeners.$$ 2>/dev/null
echo

echo "===== END OF REPORT ====="
echo

# Overall safety assessment
echo "🔒 OVERALL SAFETY ASSESSMENT:"

remote_login_enabled=$(sudo systemsetup -getremotelogin 2>/dev/null | grep -o "On\|Off")
# Re-evaluate firewall state for recommendations
fw_cli_raw_assess=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
fw_cli_state_assess=$(grep -oE 'State = [0-9]+' <<< "$fw_cli_raw_assess" 2>/dev/null | awk '{print $3}')
fw_plist_state_assess=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "")
fw_state_assess="${fw_cli_state_assess:-$fw_plist_state_assess}"

has_dropbox_lan=false
for port in 17500 17600 17603; do
  if lsof -iTCP:$port -sTCP:LISTEN >/dev/null; then
    has_dropbox_lan=true
    break
  fi
done
has_dropbox_lan=$(if [[ "$has_dropbox_lan" == true ]]; then echo "yes"; else echo "no"; fi)

# Only treat Java listeners as a concern if they are not local-only
has_java_network_listeners=$(lsof -i -P -n | grep LISTEN | grep java | grep -Ev '127\.0\.0\.1:|::1:' >/dev/null && echo "yes" || echo "no")

firewall_is_off=false
if [[ "$fw_state_assess" == "0" || -z "$fw_state_assess" ]]; then
  firewall_is_off=true
fi

if [[ "$remote_login_enabled" == "On" ]] || [[ "$has_dropbox_lan" == "yes" ]] || [[ "$has_java_network_listeners" == "yes" ]] || [[ "$firewall_is_off" == true ]]; then
  echo "⚠️  CAUTION: Potential security concerns detected."
  echo
  echo "🔧 RECOMMENDED ACTIONS:"
  
  if [[ "$remote_login_enabled" == "On" ]]; then
    echo "• Turn off Remote Login: System Preferences → Sharing → uncheck 'Remote Login'"
  fi
  
  if [[ "$has_dropbox_lan" == "yes" ]]; then
    echo "• Disable Dropbox LAN sync: Dropbox → Preferences → Sync → uncheck 'Enable LAN sync'"
  fi
  
  if [[ "$has_java_network_listeners" == "yes" ]]; then
    echo "• Review Java applications: At least one Java process is listening on a network-visible interface; confirm you recognize and need it"
  fi
  
  if [[ "$firewall_is_off" == true ]]; then
    echo "• Enable macOS Firewall: System Settings → Network → Firewall → Turn On"
  fi
else
  echo "✅  System appears secure. No obvious security issues found."
fi

echo
echo "Success"

exit 0
