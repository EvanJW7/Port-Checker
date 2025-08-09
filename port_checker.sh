#!/bin/bash

echo "===== PORT WATCHDOG REPORT ====="
echo

# 1. Show all listening ports
echo "🔍 Listening Ports:"
lsof -i -P -n | grep LISTEN
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

# 4. Check if macOS firewall is enabled
echo "🔥 Firewall Status:"
fw_status=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
if [[ "$fw_status" == "1" ]]; then
  echo "✅ Firewall is ON"
elif [[ "$fw_status" == "0" ]]; then
  echo "⚠️ Firewall is OFF"
else
  echo "⚠️ Could not determine firewall status"
fi
echo

# 5. Check for active Java processes with listening ports
echo "☕ Java Listening Check:"
java_listeners=$(lsof -i -P -n | grep LISTEN | grep java)
if [[ -n "$java_listeners" ]]; then
  echo "⚠️ Java process is listening on:"
  echo "$java_listeners"
else
  echo "✅ No Java processes listening on ports"
fi
echo

echo "===== END OF REPORT ====="
echo

# Overall safety assessment
echo "🔒 OVERALL SAFETY ASSESSMENT:"
# Check for actual security risks (not just running processes)
remote_login_enabled=$(sudo systemsetup -getremotelogin 2>/dev/null | grep -o "On\|Off")
# Check for any Dropbox LAN sync ports
has_dropbox_lan=false
for port in 17500 17600 17603; do
  if lsof -iTCP:$port -sTCP:LISTEN >/dev/null; then
    has_dropbox_lan=true
    break
  fi
done
has_dropbox_lan=$(if [[ "$has_dropbox_lan" == true ]]; then echo "yes"; else echo "no"; fi)
has_java_listeners=$(lsof -i -P -n | grep LISTEN | grep java >/dev/null && echo "yes" || echo "no")

if [[ "$remote_login_enabled" == "On" ]] || [[ "$has_dropbox_lan" == "yes" ]] || [[ "$has_java_listeners" == "yes" ]]; then
  echo "⚠️  CAUTION: Potential security concerns detected."
  echo
  echo "🔧 RECOMMENDED ACTIONS:"
  
  if [[ "$remote_login_enabled" == "On" ]]; then
    echo "• Turn off Remote Login: System Preferences → Sharing → uncheck 'Remote Login'"
  fi
  
  if [[ "$has_dropbox_lan" == "yes" ]]; then
    echo "• Disable Dropbox LAN sync: Dropbox → Preferences → Sync → uncheck 'Enable LAN sync'"
  fi
  
  if [[ "$has_java_listeners" == "yes" ]]; then
    echo "• Review Java applications: Check what Java processes are running and close unnecessary ones"
  fi
  
  echo "• Enable macOS Firewall: System Preferences → Security & Privacy → Firewall → Turn On"
else
  echo "✅  System appears secure. No obvious security issues found."
fi
