---
description: Scaffold + setup a new engagement (rh_init then rh_kickoff)
agent: redhunter
---
Initialize the engagement for target `$ARGUMENTS`. Run, from ~/.config/opencode/skill/redhunting:
`source ~/.rh-tools/env.sh && python3 bin/rh_init.py $ARGUMENTS` then `python3 bin/rh_kickoff.py $ARGUMENTS`.
Answer the three setup questions with me, then confirm the random identity and the A/B accounts. Do NOT touch any target host until scope is set.
