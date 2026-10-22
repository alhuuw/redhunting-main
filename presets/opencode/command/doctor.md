---
description: Environment readiness check (skip-not-fail tools)
agent: redhunter
---
Run `source ~/.rh-tools/env.sh && python3 bin/rh_doctor.py` from ~/.config/opencode/skill/redhunting and summarize READY vs missing. Missing optional tools degrade the loop, never block it. Do not install anything unless I ask.
