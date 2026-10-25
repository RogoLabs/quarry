"""Layer 3: dynamic validation.

Layers 1 and 2 read the target. Layer 3 runs it. A finding that survives the funnel
is a *candidate*: a claim about the code that is still only argued, never executed.
Layer 3's job is to turn that claim into one of two durable outcomes, both backed by a
reproducible artifact rather than a model's opinion:

  * confirmed  — a probe exercised the finding against a running instance of the target
                 and observed the predicted effect. The verdict carries the probe and
                 the measured evidence, so a maintainer can replay it.
  * rejected   — the probe ran and the finding did not reproduce. Killed with evidence,
                 not with "looks defended".

Anything the probe could not decide stays `needs-review`; Layer 3 never upgrades a
guess into a confirmation. This is the only thing that writes a non-zero
`executed_score` into the verdict ledger.

Which probe runs is chosen per codebase, not hardcoded: `lenses.select_probe_lenses`
reads the same `research.profile` the deep layer uses and runs a probe only when the
artifact is runnable, the capability is present, and a surviving finding matches.

Containment: the target is executed under `quarry-target.sb` (loopback only) for a
single-process target, or via the Docker runtime on an egress-blocked internal network
(`runtime_docker`). Running a target is running untrusted code, so it happens with
nothing reachable off the machine.
"""
from .validate import (  # noqa: F401
    Candidate, ProbeEvidence, RuntimeSpec, RunningTarget, TargetRuntime,
    DYNAMICALLY_TESTABLE, select_candidates, adjudicate, record_verdict,
    plan_validation, ValidationPlan, run_validation, ValidationResult, register_runtime,
)
from .lenses import ProbeLens, CATALOGUE, select_probe_lenses  # noqa: F401
from .routes import (  # noqa: F401
    Route, RouteMap, RouteSource, StaticRouteSource, OpenApiFileRouteSource,
    build_route_map, routes_from_openapi, fetch_openapi_routes, crawl_routes,
)
from .probes import (  # noqa: F401
    probe_broken_authz, probe_missing_rate_limit, probe_auth_timing_oracle,
    probe_injection_observable, probe_path_traversal_ssrf)
