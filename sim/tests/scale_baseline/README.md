# scale_baseline

**Purpose**: find the practical host-count ceiling on this machine, and
whether memory or wall-clock binds first.

## Machine

64 threads, 251 GB RAM, 128 GB Optane swap plus 900 GB on NVMe. Shadow
3.2.0, 60 worker threads, all-honest hosts, 15 min simulated, seed 42.
Output on `/fast/tmp` (Optane).

## Results

| hosts | wall-clock | sim/real | run memory | MB/host | output | honest1 discovered |
|------:|-----------:|---------:|-----------:|--------:|-------:|-------------------:|
| 700   | 7.3 min    | 2.07x    | 23 GB      | 33      | 0.6 GB | 611 |
| 1500  | 20.3 min   | 0.74x    | 60 GB      | 40      | 2.3 GB | 1444 |
| 3000  | 43.1 min   | 0.35x    | 156 GB     | 52      | 7.4 GB | 2860 |
| 5000  | aborted by the memory guard before starting | | | | | |

Run memory is the delta this run added on top of what the box was already
using; absolute peaks were 63, 99 and 196 GB.

## What we learned

- **Memory per host grows with host count.** 33, 40, 52 MB/host at 700,
  1500, 3000. The store and gossip state scale with the number of
  transpeers each node knows, so the old 40 MB/host rule of thumb
  under-projects large runs. Projected 5000-host need is roughly 270 GB,
  which exceeds RAM and would spill about 50 GB into Optane swap.
- **Wall-clock is between linear and N^1.35**, not the N^2 the old notes
  feared. 60 workers keep gossip cost parallel. A 5000-host run would be
  around 1.5 hours if memory allowed.
- **So memory binds first after all**, just at 4x the old ceiling rather
  than at 700. The guard aborted 5000 because it budgets against
  available RAM only; letting it count Optane swap is the way to push
  past 3000, and is untested.
- **Output is 2.5 MB per host** of stderr per 15 simulated minutes, and
  compresses about 12x. Archived tarballs for the three runs total 0.85 GB.

## Recommendations for sizing other tests

- Up to 3000 hosts: run freely, budget an hour and 160 GB.
- 3000 to 5000: relax `MEM_HEADROOM_PCT` or count swap in the guard, run
  alone on the box, and expect swap activity.
- bootstrap_eclipse's largest cells are 1551 hosts and fit comfortably.

## Previous machine, for comparison

Ryzen 9 3900X, 31 GB: 700 hosts took 27 minutes and 27 GB plus 2.3 GB of
slow swap. Same host count here took 7 minutes and 23 GB, with 60 workers
instead of 6.
