#!/bin/bash

get_remote_login_status() {
  # Best-effort, passwordless check using launchctl instead of sudo systemsetup
  if launchctl print system/com.openssh.sshd 2>/dev/null | grep -q "active = true"; then
    echo "On"
  else
    echo "Off"
  fi
}

has_nonapple_network_visible="no"
has_remote_access_tools="no"
has_third_party_startup="no"
has_pending_updates="no"

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
  remote_login_status=$(get_remote_login_status)
  if [[ "$remote_login_status" == "On" ]]; then
    echo "⚠️ 'remoted' is running AND Remote Login is ENABLED — Security risk!"
  else
    echo "ℹ️ 'remoted' is running but Remote Login is DISABLED — Normal system behavior"
  fi
else
  echo "✅ 'remoted' not running"
fi
echo

# 3. Check key macOS sharing services
echo "📡 Sharing Services:"
remote_login_pref=$(get_remote_login_status)
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

# 7. Highlight network-visible non-Apple services
echo "🌐 Network-visible Non-Apple Services:"
tmp_nv=/tmp/ports_watchdog_network_visible.$$
lsof -i -P -n | grep LISTEN > "$tmp_nv" 2>/dev/null

tmp_nv_filtered=/tmp/ports_watchdog_network_visible_filtered.$$
> "$tmp_nv_filtered"

while IFS= read -r line; do
  process=$(awk '{print $1}' <<< "$line")
  address_port=$(grep -oE '[0-9a-fA-F\.:]+:[0-9]+' <<< "$line" | tail -n 1)
  bind_addr="${address_port%:*}"

  # Only care about services bound to all interfaces / network-visible
  if [[ "$bind_addr" != "0.0.0.0" && "$bind_addr" != "*" && "$bind_addr" != "::" ]]; then
    continue
  fi

  # Skip common Apple/system daemons
  case "$process" in
    rapportd|mDNSResponder|configd|socketfilterfw|apsd|trustd|softwareupdated|powerd|UserEventAgent|opendirectoryd|syslogd)
      continue
      ;;
  esac

  echo "$line" >> "$tmp_nv_filtered"
done < "$tmp_nv"

if [[ -s "$tmp_nv_filtered" ]]; then
  has_nonapple_network_visible="yes"
  cat "$tmp_nv_filtered"
  echo "⚠️ Review the above apps; they are reachable from other devices on your network."
else
  echo "✅ No obvious third-party services listening on all interfaces."
fi

rm -f "$tmp_nv" "$tmp_nv_filtered" 2>/dev/null
echo

# 8. Check for common remote-access tools
echo "🖥️ Remote Access Tools Check:"
remote_tools=("TeamViewer" "teamviewerd" "AnyDesk" "anydesk" "RustDesk" "rustdesk" "LogMeIn" "logmein" "Splashtop" "splashtop" "Parsec" "parsecd" "Chrome Remote Desktop" "remotedesktop" "VNC" "Screen Sharing")
remote_found=false

for name in "${remote_tools[@]}"; do
  if pgrep -fi "$name" >/dev/null 2>&1; then
    if [[ "$remote_found" == false ]]; then
      echo "⚠️ The following remote-access related processes are running:"
      echo "   These tools can provide full or partial remote control of your Mac over the network."
    fi
    remote_found=true
    has_remote_access_tools="yes"

    # Show details for each matching process
    pgrep -fl "$name" 2>/dev/null | while read -r line; do
      pid=${line%% *}
      cmd=${line#* }
      app_path=$(grep -oE '/Applications/[^ ]+\.app' <<< "$cmd" | head -n 1)

      # Human-friendly description based on the tool name
      desc=""
      case "$name" in
        TeamViewer|teamviewerd)
          desc="TeamViewer: remote support/remote desktop app that allows full remote control when signed in or when a session is started."
          ;;
        AnyDesk|anydesk)
          desc="AnyDesk: remote desktop tool for unattended access and screen control over the internet."
          ;;
        RustDesk|rustdesk)
          desc="RustDesk: open-source remote desktop application that can use public or self-hosted relay servers."
          ;;
        LogMeIn|logmein)
          desc="LogMeIn: remote access software for persistent remote control of this machine."
          ;;
        Splashtop|splashtop)
          desc="Splashtop: remote desktop/remote support tool used to access this Mac from other devices."
          ;;
        Parsec|parsecd)
          desc="Parsec: high-performance remote streaming app, often used for gaming or low-latency remote desktops."
          ;;
        "Chrome Remote Desktop"|remotedesktop)
          desc="Chrome Remote Desktop: Google remote access extension/service for sharing this Mac's screen via a Google account."
          ;;
        VNC|"Screen Sharing")
          desc="VNC/Screen Sharing: built-in or third-party screen sharing service that allows remote viewing/control."
          ;;
      esac

      echo "$line"
      if [[ -n "$app_path" ]]; then
        echo "    → App bundle: $app_path"
      fi
      if [[ -n "$desc" ]]; then
        echo "    → Description: $desc"
      else
        echo "    → Description: Remote-access or screen-sharing related process; review its settings or uninstall if not needed."
      fi
    done
  fi
done

if [[ "$remote_found" == false ]]; then
  echo "✅ No common remote-access tools detected as running (TeamViewer, AnyDesk, RustDesk, etc.)."
fi
echo

# 9. Startup & background items overview
echo "🧩 Startup & Background Items:"
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  if [[ -d "$dir" ]]; then
    count=$(ls "$dir" 2>/dev/null | wc -l | tr -d ' ')
    echo "$dir: $count items"
    echo "  (Each .plist here is a launch agent/daemon that can start automatically in the background.)"

    ls "$dir" 2>/dev/null | head -n 10 | while read -r item; do
      if [[ -z "$item" ]]; then
        continue
      fi
      if [[ "$item" == com.apple.* ]]; then
        kind="Apple/system"
      else
        kind="Third-party"
        has_third_party_startup="yes"
      fi
      echo "  - $item ($kind launch item; installed and managed by its corresponding app/service)"
    done

    if (( count > 10 )); then
      echo "… (showing first 10)"
    fi
    echo
  fi
done
echo "ℹ️ Review third-party items above; they can run at login or in the background."
echo

# 10. Browser & extensions reminder
echo "🌐 Browser & Extensions Reminder:"
echo "• Periodically review installed browser extensions and remove ones you don't fully trust or use."
echo "• Ensure your main browser profile is protected by a strong account password and two-factor authentication."
echo

# 11. macOS update status
echo "🧱 macOS Update Status:"
if updates_output=$(softwareupdate -l 2>/dev/null); then
  if grep -q "No new software available." <<< "$updates_output"; then
    echo "✅ No pending macOS software updates reported."
  else
    has_pending_updates="yes"
    echo "⚠️ macOS reports available updates:"
    echo "$updates_output"
  fi
else
  echo "⚠️ Could not determine update status (softwareupdate command failed)."
fi
echo "ℹ️ Also ensure App Store apps (including Xcode) are up to date via the App Store."
echo

echo "===== END OF REPORT ====="
echo

# Overall safety assessment
echo "🔒 OVERALL SAFETY ASSESSMENT:"

remote_login_enabled=$(get_remote_login_status)
# Re-evaluate firewall state for recommendations
fw_cli_raw_assess=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
fw_cli_state_assess=$(grep -oE 'State = [0-9]+' <<< "$fw_cli_raw_assess" 2>/dev/null | awk '{print $3}')
fw_plist_state_assess=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "")
fw_state_assess="${fw_cli_state_assess:-$fw_plist_state_assess}"

# Only treat Java listeners as a concern if they are not local-only
has_java_network_listeners=$(lsof -i -P -n | grep LISTEN | grep java | grep -Ev '127\.0\.0\.1:|::1:' >/dev/null && echo "yes" || echo "no")

firewall_is_off=false
if [[ "$fw_state_assess" == "0" || -z "$fw_state_assess" ]]; then
  firewall_is_off=true
fi

if [[ "$remote_login_enabled" == "On" ]] || [[ "$has_java_network_listeners" == "yes" ]] || [[ "$firewall_is_off" == true ]] || \
   [[ "$has_nonapple_network_visible" == "yes" ]] || [[ "$has_remote_access_tools" == "yes" ]] || \
   [[ "$has_third_party_startup" == "yes" ]] || [[ "$has_pending_updates" == "yes" ]]; then
  echo "⚠️  CAUTION: Potential security concerns detected."
  echo
  echo "🔧 RECOMMENDED ACTIONS:"
  
  if [[ "$remote_login_enabled" == "On" ]]; then
    echo "• Turn off Remote Login: System Preferences → Sharing → uncheck 'Remote Login'"
  fi

  if [[ "$has_java_network_listeners" == "yes" ]]; then
    echo "• Review Java applications: At least one Java process is listening on a network-visible interface; confirm you recognize and need it"
  fi
  
  if [[ "$firewall_is_off" == true ]]; then
    echo "• Enable macOS Firewall: System Settings → Network → Firewall → Turn On"
  fi

   if [[ "$has_nonapple_network_visible" == "yes" ]]; then
     echo "• Review 'Network-visible Non-Apple Services' and disable or restrict any apps you don't recognize or actively use."
   fi

   if [[ "$has_remote_access_tools" == "yes" ]]; then
     echo "• Review remote-access tools: keep only those you trust and need, and ensure they use strong passwords and two-factor authentication."
   fi

   if [[ "$has_third_party_startup" == "yes" ]]; then
     echo "• Review third-party launch agents/daemons listed under 'Startup & Background Items' and remove or disable anything unnecessary."
   fi

   if [[ "$has_pending_updates" == "yes" ]]; then
     echo "• Install pending macOS software updates and update App Store apps (including Xcode) via the App Store."
   fi
else
  echo "✅  System appears secure. No obvious security issues found."
fi

echo
echo "Success"

exit 0
