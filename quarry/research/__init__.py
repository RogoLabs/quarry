"""Deep mode — multi-model whole-repository review.

Distinct from the gated Layer 2R design in `docs/LAYER2-PLAN.md`, which optimises
precision across many repositories by having a deterministic detector emit a small
anomaly cohort for one model to adjudicate.

Deep mode is the other product: one repository, several model *families* reading it
independently through profile-selected lenses, then refuting each other. It trades
throughput for coverage, which is the right trade when the question is "is there
anything here at all" rather than "which of these 2,277 findings matter".

The two are complementary and share the funnel, the ledger and the triage UI.
"""
from .pack import Pack, pack_repo                    # noqa: F401
from .profile import RepoProfile, profile_repo       # noqa: F401
