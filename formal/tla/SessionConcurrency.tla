---- MODULE SessionConcurrency ----
EXTENDS Naturals, FiniteSets

CONSTANTS Sessions, MaxCounter

VARIABLES active, live, durable, emitted, epoch

vars == <<active, live, durable, emitted, epoch>>

Init ==
    /\ active = {}
    /\ live = [s \in Sessions |-> 0]
    /\ durable = [s \in Sessions |-> 0]
    /\ emitted = {}
    /\ epoch = 0

\* Same-session ops serialize via `active`. Distinct sessions may Begin independently.
Begin(s) ==
    /\ s \in Sessions
    /\ s \notin active
    /\ live[s] < MaxCounter
    /\ active' = active \cup {s}
    /\ UNCHANGED <<live, durable, emitted, epoch>>

\* Successful commit advances live, durable, and the emitted (session, counter) set together.
CommitAndEmit(s) ==
    /\ s \in active
    /\ live[s] < MaxCounter
    /\ live' = [live EXCEPT ![s] = @ + 1]
    /\ durable' = [durable EXCEPT ![s] = @ + 1]
    /\ emitted' = emitted \cup {<<s, live[s] + 1>>}
    /\ epoch' = epoch + 1
    /\ active' = active \ {s}

\* Failed operations leave counters and emissions unchanged.
Abort(s) ==
    /\ s \in active
    /\ active' = active \ {s}
    /\ UNCHANGED <<live, durable, emitted, epoch>>

\* Bounded-model terminal: every session has reached MaxCounter and no op is in flight.
Terminal ==
    /\ active = {}
    /\ \A s \in Sessions : live[s] = MaxCounter

TerminalStutter ==
    /\ Terminal
    /\ UNCHANGED vars

Next ==
    \/ \E s \in Sessions : Begin(s) \/ CommitAndEmit(s) \/ Abort(s)
    \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ active \subseteq Sessions
    /\ live \in [Sessions -> 0..MaxCounter]
    /\ durable \in [Sessions -> 0..MaxCounter]
    /\ emitted \subseteq (Sessions \X (1..MaxCounter))
    /\ epoch \in Nat

\* Per-session progress: durable never exceeds live, and live stays in bounds.
PerSessionProgress ==
    \A s \in Sessions :
        /\ durable[s] <= live[s]
        /\ live[s] <= MaxCounter

\* This commit protocol writes live and durable together.
LiveEqualsDurable ==
    \A s \in Sessions : live[s] = durable[s]

\* Emitted counters for a session are exactly 1..durable[s], so they are unique
\* and never committed on Abort.
EmittedArePrefix ==
    \A s \in Sessions :
        \A c \in 1..MaxCounter :
            (<<s, c>> \in emitted) <=> (c <= durable[s])

NoDuplicateEmission ==
    \A m1 \in emitted :
        \A m2 \in emitted :
            (m1[1] = m2[1] /\ m1[2] = m2[2]) => m1 = m2

EpochEqualsTotalCommits == epoch = Cardinality(emitted)

====
