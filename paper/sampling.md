# Sampling rule for the stratified run

Implemented by `tools/common/draw_sample.py`. The draw's manifest is `reports/_draws/<sample-id>.json`.

## Frame

Each dataset repo is pinned at one commit. It is listed in full with git, from a treeless clone. The GitHub tree
API truncates the Datadog listing and silently hid about a third of it, including all of Datadog's PyPI.

| Corpus | Ecosystem | Stratum | Package names |
|---|---|---|---|
| Datadog malicious-software-packages | npm | `compromised_lib`, 2024 / 2025 / 2026 | 4 / 589 / 411 |
| Datadog malicious-software-packages | npm | `malicious_intent`, 2024 / 2025 / 2026 | 4,059 / 6,420 / 2,511 |
| Datadog malicious-software-packages | PyPI | `compromised_lib` | 17 |
| Datadog malicious-software-packages | PyPI | `malicious_intent` | 1,815 |
| pypi_malregistry | PyPI | sdist / wheel / zip | 10,366 / 185 / 17 |

The year is the date in the Datadog archive name. Datadog's `ai-skills` folder is not packages, so it is out of
the frame. pypi_malregistry paths carry no label or date.

## Unit

One version per package name, with PyPI names compared per PEP 503 across both corpora. Many names have several
versions, and those are near-copies. A name in both PyPI corpora counts once. Campaigns that remain are folded by
the cluster key into members after `prepare.py`.

## Size and allocation

500 names, split evenly between the ecosystems: 250 npm and 250 PyPI.

- **npm:** 100 from `compromised_lib`, oversampled because worms and hijacked libraries carry the most complex
  gates, and 150 from `malicious_intent`. Within each label, years get shares in proportion to their names, with
  at least 10 per non-empty year, or every name the year has if it has fewer.
- **PyPI:** every Datadog `compromised_lib` name (the PyPI counterpart of the npm hijacks). The rest is shared in
  proportion to names across Datadog `malicious_intent` and the pypi_malregistry archive kinds. Wheels and zips
  have no install code and end as skips; they are drawn anyway so skip rates have honest denominators.

## Draw

Within a stratum, archives are taken in `sha256(seed | path)` order, keeping the first version met for each name,
until the quota is filled. Compromised strata are drawn first. The seed is fixed before the draw. The manifest
records the seed, each repo's commit, every stratum's name count N and draw n, and every drawn archive with its git
blob sha. `--fetch` downloads from the pinned commits and checks every file against its blob sha. The manifest is
committed; the archives are not.

## Estimates

Every prevalence figure is reported per stratum, and as a total weighted by design. The design weight of a drawn
name in stratum h is N_h / n_h (the released `weight` column). The estimates reweight over the names that responded,
so a responding name counts N_h / r_h, where r_h is the number of respondents in the stratum; with no non-response
the two are equal. Unweighted pooled numbers over-represent the oversampled compromised strata, and must not be
quoted as corpus prevalence.

After the draw was analysed and before any figure was frozen, one typosquat family turned out to hold nearly half
of the weighted PyPI names with install code (47%; 37% of all weighted PyPI names, and 70 of the 196 malregistry
sdist names), so names are not independent. The design and the drawn names are unchanged, and the estimates handle
this in two ways. Intervals resample whole campaigns (respondents
sharing a cluster_key) within each stratum instead of single names, and every figure is also reported per campaign:
each install-code campaign with a responding name counts once, unweighted, with a bootstrap over campaigns. The
summary also gives the fewest campaigns holding half the weighted gated names, so a reader can see how concentrated
a name-weighted share is.

After review, each ecosystem total also gained these checks, which leave the point estimates unchanged:

- **Non-response bounds** (`bound_low`, `bound_high`): the share with every non-responding drawn name counted as an
  install-code name that is ungated (low) or gated (high). Non-response is not missing at random here, since refusals
  fall on obfuscated worm bundles.
- **Merged interval** (`ci_low_merged`, `ci_high_merged`): the bootstrap again, with the campaigns that hold half the
  weighted gated names folded into one cluster. For PyPI those are three cluster keys of the one dropper family,
  so this is the interval at family level.
- **Gated on the environment** (measure `gated_env`): gated by a kept gate with an in-scope condition that is not a
  target artifact, the narrower sense in which earlier studies count environment checks.
- **Gated beyond absence** (measure `gated_not_absence`): gated by a kept gate with a condition other than a check
  that a file is absent. Most gated PyPI names are Windows droppers whose only check is that a marker file is
  absent, which passes on any fresh machine; this measure shows the share without them.
- **Per-label totals**: npm's year strata are also summed per label (`compromised_lib`, `malicious_intent`), so the
  two labels' gated shares can be compared directly.

## The 164 local samples

They are a pilot, taken alphabetically, not at random. They are kept out of the headline numbers. A drawn name
already in the pilot reuses its record when the version matches, or by name alone when the drawn archive's path
carries no version. The 160 pilot archives no draw holds are pinned
in `reports/_draws/pilot.json` (`draw_sample.py --pilot`) at the commits the draw pinned, each with its git blob
sha, so `draw_sample.py --sample-id pilot --fetch` reproduces them.

## Benign control set

Implemented by `tools/common/draw_benign.py`; manifest `reports/_draws/benign.json`. 25 npm and 25 PyPI
packages, the most-downloaded that run code at install time, are analysed, verified and repaired like the
malicious records. npm: every name of npm-high-impact's download list (pinned by
version and integrity) whose latest version declares `preinstall`, `install` or `postinstall`, or ships a
`binding.gyp`, ranked by the npm downloads API's last-month counts. Install scripts are rare among the most
downloaded packages (138 of the 15,910 names the registry still serves), so qualifying comes before ranking. PyPI: the
top-pypi-packages 30-day list (pinned by its `last_update` and SHA-256), in rank order; a package qualifies when its
latest release has an sdist with `setup.py` at its root. The manifest records each package's rank, downloads,
version and archive SHA-256; the set is a purposive sample with no design weight.
