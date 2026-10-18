# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

The triage roles are states; the repo's older category labels (`Bug`, `Request`, `Enhancement`,
`Added`, `Chore`, `Documentation`, `Dependencies`, `Breaking change`, `Help wanted`) say what kind
of issue it is. An issue normally carries one of each.

The five labels have to exist on the repository before they can be applied. Create them once with:

```sh
gh label create needs-triage    --color e4e669 --description "Maintainer needs to evaluate this issue"
gh label create needs-info      --color d876e3 --description "Waiting on reporter for more information"
gh label create ready-for-agent --color 0e8a16 --description "Fully specified, ready for an AFK agent"
gh label create ready-for-human --color 1d76db --description "Requires human implementation"
gh label create wontfix         --color ffffff --description "Will not be actioned"
```
