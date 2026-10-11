#!/usr/bin/env bash
# Regenerates the images in art/ from the demo. Run it after changing the
# report, the mail or the demo page, then commit art/.
#
# Needs PHP (with the dev dependencies installed), Python 3 and a Chrome or
# Chromium binary: set CHROME=/path/to/chrome if it isn't on the PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

CHROME=${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || command -v chrome-headless-shell || true)}
[ -x "$CHROME" ] || { echo "Chrome not found; set CHROME=/path/to/chrome" >&2; exit 1; }

rm -rf build
php demo/build.php build/site build/shots
mkdir -p art build/serve
ln -sfn ../site build/serve/laravel-security-alerts
ln -sfn ../shots build/serve/shots
cp demo/banner.html demo/ruvelo-mark.svg build/serve/

port=8937
python3 -m http.server "$port" --bind 127.0.0.1 --directory build/serve >/dev/null 2>&1 &
server=$!
trap 'kill $server' EXIT
sleep 1

shot() { # name, path, width,height, [extra chrome flags]
    "$CHROME" --headless --no-sandbox --hide-scrollbars --force-device-scale-factor=2 \
        --virtual-time-budget=5000 ${4:-} --window-size="$3" \
        --screenshot="art/$1.png" "http://127.0.0.1:$port/$2" 2>/dev/null
    echo "art/$1.png"
}

shot screenshot-page     shots/page/      1440,900
shot screenshot-report   shots/report/    1440,1180
shot screenshot-terminal shots/terminal/  1440,1060
shot screenshot-mail     shots/mail/      900,1400
shot screenshot-dark     shots/report/    1440,900 --blink-settings=preferredColorScheme=0
shot screenshot-mobile   shots/report/    390,844

# The banner frames the report screenshot, so it goes last.
mkdir -p build/site/art && cp art/screenshot-report.png build/site/art/
shot banner banner.html 1280,640
