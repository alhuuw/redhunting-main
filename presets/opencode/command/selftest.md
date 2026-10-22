---
description: Verify the skill itself is intact (doctor + regression suite)
agent: redhunter
---
Run `source ~/.rh-tools/env.sh && python3 bin/rh_doctor.py && python3 -m unittest discover -s tests` from ~/.config/opencode/skill/redhunting. Report the doctor verdict and the test count. If anything fails, show the failing output verbatim.
