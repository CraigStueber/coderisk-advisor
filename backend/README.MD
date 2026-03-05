# CodeRisk Advisor — Graph Layer

## What lives here

```
graph/
├── state.py        # Shared state schema (Pydantic + TypedDict)
├── supervisor.py   # Graph assembly + routing logic + model registry
└── nodes/
    └── nodes.py    # All five agent node implementations
```

## Architecture decisions and why

### State as typed Pydantic models, not raw dicts

Every agent output (VulnerabilityFinding, BehavioralRiskFinding, etc.) is a
Pydantic model. This forces the LLM output parsing to validate before it
reaches downstream nodes. Failures surface immediately at the node boundary
rather than as cryptic KeyErrors later in the graph.

Raw dicts would be faster to prototype but would hide contract violations
between agents. At the scale of a portfolio demo this doesn't matter
operationally, but it matters as a signal to a technical audience reviewing
the code.

### Supervisor pattern over simple chain

The supervisor node makes routing decisions after every agent completion.
This means:

- Adding a new agent is a node registration + routing rule, not a chain
  restructure
- The Skeptic can be conditionally skipped (e.g. zero findings)
- Remediation only runs when the user actually asks for it, not every turn

A simple chain (scanner -> skeptic -> remediation -> synthesizer) would
run all agents every turn regardless of what the user asked. That is
wasteful and doesn't model real review panel behavior.

### Parallel fan-out for scanners

VulnScanner and BehavioralRisk run in parallel on new submissions.
They operate on the same input (raw code) and produce independent outputs
(vuln_findings vs behavioral_findings). There is no dependency between them.

Sequential execution would add latency for no correctness benefit.

### Skeptic as a first-class agent

Most security scanner demos skip this entirely. The Skeptic node is the
architectural differentiator. It:

- Reviews all findings after both scanners complete
- Disputes overconfident findings with rationale
- Adjusts the effective severity of the overall analysis
- Makes the system behave like a review panel, not a rubber stamp

For the dissertation connection: the Skeptic operationalizes the concept
of confidence calibration in AI-generated assessments. A finding with
confidence=0.9 that the Skeptic disputes is a better signal than a
finding with confidence=0.5 that passes unchallenged.

### Synthesizer owns the user-facing response

No other node writes to synthesized_response. The Synthesizer reads
all agent outputs and shapes them into a conversational reply appropriate
to the current turn. This separation means:

- Agents focus on analysis, not presentation
- The tone and framing of responses can be tuned in one place
- The synthesizer can decide how much detail to surface based on
  what the user actually asked

### Error handling: write, don't raise

Nodes catch their own exceptions and write to state.errors rather than
letting exceptions propagate. This keeps the graph alive across a
partial failure. If VulnScanner fails but BehavioralRisk succeeds,
the user still gets a partial analysis rather than a 500.

The Synthesizer checks state.errors and surfaces them transparently.

## Extending the graph

To add a new agent:

1. Define its output model in state.py
2. Add its role to AgentRole enum
3. Add its model to MODELS in supervisor.py
4. Implement run\_<agent> in nodes/
5. Register the node and edges in build_graph()
6. Add routing logic to the supervisor function

The routing function (route_from_supervisor) is the only place that
needs to know about sequencing. Nodes remain unaware of each other.

## Swapping the checkpointer for Cloud Run

MemorySaver (current) keeps state in process memory.
For Cloud Run with multiple replicas:

```python
from langgraph.checkpoint.redis import RedisSaver
checkpointer = RedisSaver(redis_url=os.environ["REDIS_URL"])
```

Add a Redis instance to your Cloud Run service configuration.
Session IDs map 1:1 to LangGraph thread IDs, so no other changes needed.
