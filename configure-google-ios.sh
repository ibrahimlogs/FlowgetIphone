#!/bin/zsh
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: zsh configure-google-ios.sh '<ios-client-id>.apps.googleusercontent.com'" >&2
  exit 64
fi

client_id="$1"
suffix=".apps.googleusercontent.com"
if [[ "$client_id" != *"$suffix" ]]; then
  echo "The value must be the Google OAuth client ID created for the com.flowget.ios iOS app." >&2
  exit 64
fi

identifier="${client_id%$suffix}"
reversed_client_id="com.googleusercontent.apps.${identifier}"
script_dir="${0:A:h}"
plist_path="${script_dir}/Info.plist"

/usr/bin/plutil -replace GIDClientID -string "$client_id" "$plist_path"
/usr/bin/plutil -replace CFBundleURLTypes.1.CFBundleURLSchemes.0 -string "$reversed_client_id" "$plist_path"

echo "Google Sign-In configured for com.flowget.ios."
echo "No OAuth client secret was stored in the project."
