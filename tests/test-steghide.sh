#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
cd "$(dirname "$0")/.."
command -v steghide >/dev/null
task_image_test=$(mktemp -d)
cc -Wall -Wextra -Werror -O2 src/service/steghide.c -lutil -o "$task_image_test/steghide-helper"
cc -Wall -Wextra -Werror -O2 tests/steghide-driver.c -o "$task_image_test/driver"
timeout 30 "$task_image_test/driver" "$task_image_test/steghide-helper" "$task_image_test"
