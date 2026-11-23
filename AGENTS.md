# Threat Atlas — agent rules

Applies to every agent (CL, MAC/MacGyver, Seek, Billy and future agents). Robert retains all owner decisions. Private project rules in the local checkout still apply; this file adds the public-safe handover rule.

## Handover
A handover is complete only when every step below is done. A comment, a chat message, a mention or a Telegram notice is not a handover.

- **MUST: change the Owner on the board at every handover.** Tasks whose Owner is left unchanged are never picked up, so this step is not optional. In the same step as the handover, and before reporting it, the sending agent sets the board item's **Owner** field to the receiving agent and swaps the `owner:` label to match. The handover note states `Owner on board: <agent>`. When acknowledging, the receiver checks that Owner shows its own name, sets it itself if it does not, and repeats `Owner on board: <agent>` in the acknowledgement. A handover where the board still shows the sender as Owner is not done.
- **Handover schedule (every hour).** Hand over in your own slot: CL at :00, MAC at :02, Seek at :04, Billy at :06. Pick up in your own slot: CL at :10, MAC at :12, Seek at :14, Billy at :16. Each handover is its own file, so agents never edit the same file at once. Run `git pull --rebase` before every push. Pickup is a plain script (no AI) that checks the board for items with Owner = you and wakes the AI only when it finds something new.
- **Owner is a field, not a sentence.** Writing "MAC owns this" in a comment, chat or Telegram does not change ownership; only the board's Owner field does. (All agents share one GitHub account, so the issue assignee cannot show the agent.)
- **One handover, one issue.** Each handover is its own issue (or a dedicated handover record in the private `handovers/` files), never a reply buried in another thread. It contains:
  - what is handed over and why, and what the receiver is asked to do (review, implement, approve layout, etc.);
  - every file with exact path, branch/commit and **SHA-256**;
  - **acceptance criteria** the receiver can check one by one;
  - known limits, blockers and what is explicitly out of scope.
- **Receiver acknowledges in the issue.** The receiver writes an acknowledgement in that issue naming the exact reference (issue number, commit, SHA-256) and either starts or states a blocker. Until that acknowledgement exists, the sender reports the item as *offered*, not *handed over*, and keeps following up.
- **Keep states separate.** Offered, acknowledged, in progress, reviewed/accepted and published are different states. Never report a later state than the evidence shows.
- **Summary for Robert.** Robert reads only what is shown to him; he does not scan files. Every handover and every acknowledgement includes a summary of at most three lines, posted where Robert reads (the issue body or comment he is notified about): what it is, who owns it now, what Robert must decide (or "nothing"), and one link. He must be able to answer yes or no from that summary alone.
- **Publishing always needs Robert's explicit approval.** An agent's review or approval (for example MAC signing off a layout) is not permission to publish, release, merge to `main` or post publicly. Ask Robert and record his answer in the issue before publishing.
- **If you are unsure who owns something, ask in the issue** and leave the Owner field unchanged rather than claiming or assigning it from a comment.
