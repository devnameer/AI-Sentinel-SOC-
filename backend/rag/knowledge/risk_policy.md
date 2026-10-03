# Risk and decision policy

## Risk levels

- LOW: adjusted risk score below 0.4 (the same boundary at which the Behavior Agent flags a session). Logged only.
- MEDIUM: 0.4 ≤ score ≤ 0.7. An incident is opened and waits for analyst approval of the recommended action.
- HIGH: score > 0.7. An incident is opened; the recommended action is at least ESCALATE. It waits for approval unless auto-execution of high-risk actions is enabled.

## How the Risk & Decision Agent adjusts the score

1. Start from the Behavior Agent's anomaly score.
2. Context from MCP tools: user baseline (new users have less reliable baselines), recent incidents for the same user, the policy thresholds.
3. Optional LLM contextual review: the LLM may move the score by at most ±0.3 and must list risk and mitigating factors. The bound prevents a single LLM answer from turning a benign event into a block, or hiding an obvious attack.
4. Repeat-offender rule: three or more prior MEDIUM-or-higher events for the same user within 24 hours add a penalty and force at least ESCALATE.

## Mitigating factors analysts commonly accept

- The activity matches the user's role (for example IT staff using USB tools).
- A known business reason (approved project, maintenance window, on-call duty).
- A new user or new device during onboarding (cold-start baseline).

## Aggravating factors

- Several independent signals in the same session (for example after-hours + first USB + leak site).
- Access to files above the user's sensitivity ceiling.
- Repeated anomalous sessions in a short period.
