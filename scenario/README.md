# Authorized scenario selection

`Select` consumes an executor-discovered catalogue for the verified `auth.FromContext`
namespace. Caller-supplied candidates are a typed **trusted catalogue boundary**, not
LLM assertions of qualification or permission. All candidates are gated by exact
objective/entity/input schema/surface/profile/version/verification/cohort identity,
capabilities, permissions, measured qualification and bounded freshness. A selected
candidate is a proposal, never an execution or authorization grant.

Ranking uses distinct exact declared constraints, observation freshness, then the
Wilson lower bound from a qualified independent measured cohort. Ties and no eligible
candidate return `needsAttention`. No model confidence or guessed reliability enters
the ranking. Qualification must still be established by real held-out evidence.
