---- MODULE SessionConcurrency ----
EXTENDS Naturals, FiniteSets

CONSTANTS Sessions, MaxCounter

VARIABLES active, live, durable, emitted, epoch

vars == <<active, live, durable, emitted, epoch>>

Init ==
    /\ active = {}
    /\ live = [s \in Sessions |-> 0]
    /\ durable = [s \in Sessions |-> 0]
    /\ emitted = [s \in Sessions |-> 0]
    /\ epoch = 0

Begin(s) ==
    /\ s \in Sessions
    /\ s \notin active
    /\ live[s] < MaxCounter
    /\ active' = active \cup {s}
    /\ UNCHANGED <<live, durable, emitted, epoch>>

CommitAndEmit(s) ==
    /\ s \in active
    /\ live[s] < MaxCounter
    /\ live' = [live EXCEPT ![s] = @ + 1]
    /\ durable' = [durable EXCEPT ![s] = @ + 1]
    /\ emitted' = [emitted EXCEPT ![s] = @ + 1]
    /\ epoch' = epoch + 1
    /\ active' = active \ {s}

Abort(s) ==
    /\ s \in active
    /\ active' = active \ {s}
    /\ UNCHANGED <<live, durable, emitted, epoch>>

Next == \E s \in Sessions : Begin(s) \/ CommitAndEmit(s) \/ Abort(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ active \subseteq Sessions
    /\ live \in [Sessions -> 0..MaxCounter]
    /\ durable \in [Sessions -> 0..MaxCounter]
    /\ emitted \in [Sessions -> 0..MaxCounter]
    /\ epoch \in Nat

LiveEqualsDurable == live = durable
ObservableEqualsDurable == emitted = durable
NoSessionExceedsLimit == \A s \in Sessions : live[s] <= MaxCounter
EpochCoversAllCommits == epoch = SumCounters(live)

SumCounters(f) ==
    IF Sessions = {} THEN 0
    ELSE LET R == {f[s] : s \in Sessions}
         IN  Cardinality({<<s, n>> : s \in Sessions, n \in 1..f[s]})

====
