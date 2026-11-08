Here are the minor items we need to fix.  When complete, change `PENDING` to `COMPLETE`

1. COSMETIC

1.1 `COMPLETE` In header, change 'SluiceGate Control Plane' to 'SluiceGate'
1.2 `COMPLETE` Under Agent Registry tab, change 'Registered Autonomous Agents' to 'Registered Agents'
1.3 `COMPLETE` Under Minion Registry tab change 'Registered Minion Runtimes' to 'Registered Minions'

2. FUNCTIONAL

2.1 `COMPLETE` Audit Events > CLEAR asks for confirmation (CANCEL or CONTINUE) and clears the displayed events only. RELOAD retrieves events from the database using the current filters; stored audit records are retained.

2.2 `COMPLETE` In the SluiceGate demo, please add a column in between ACTOR and SUMMARY labeled `Decision` that tracks the policy decision and current status.  At the moment, the EVENT is always `EXECUTION_COMPLETED` and the SUMMARY is always MISSION_COMPLETE_SUCCEEDED.  

2.3 `COMPLETE` In the SluiceGate demo, please convert the Time (UTC) to human readable local time.

2.4 `COMPLETE` Add a visual patching-policy wizard to the admin console's Policies tab.

- Add **Create New** next to **Reload from Service**. Start with a mostly blank policy containing `default: BLOCK` and no rules; allow it to be deployed without adding rules.
- Guide administrators through adding patching rules, including target servers, patch sources and types, reboot permission, maintenance windows, and approval requirements. Generate YAML into the existing editor for review and manual editing.
- Add **Download YAML** and **Load YAML** for saving and loading files on the administrator's computer. Loading or generating a policy creates a draft only.
- Keep validation and the existing explicit, confirmed **Save and Activate** workflow, including backup and concurrent-change protection. Warn before replacing unsaved edits.
- Preserve imported or manually edited policy content that the wizard cannot represent; do not silently discard unsupported rules or settings.
- Reuse the existing authenticated policy endpoints and shared validation, and evaluate reusable concepts from the older visual editor without exposing its unauthenticated service.

3. DEFERRED
3.1 Change the patching registry from CSV to SQL
3.2 Implement intelligent multi-Minion load balancing
3.3 Add installer verification of every bundle artifact against SHA256SUMS.txt (see P2.1 under Minion_Feature_Plan.md)
3.4 Console RBAC model (see P2.2 under Minion_Feature_Plan.md)
3.5 Add health check features (see P2.3 under Minion_Feature_Plan.md)
3.6 Support URI-based patch package sources (see P2.4 Minion_Feature_Plan.md)
