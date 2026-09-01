---- MODULE RollbackCoordination ----
EXTENDS Naturals

CONSTANT MaxEpoch

VARIABLES local, anchor, pending, phase

vars == <<local, anchor, pending, phase>>
Phases == {"Idle", "Prepared", "LocalCommitted", "Recovery"}

Init ==
    /\ local = 0
    /\ anchor = 0
    /\ pending = 0
    /\ phase = "Idle"

Prepare ==
    /\ phase = "Idle"
    /\ anchor < MaxEpoch
    /\ pending' = anchor + 1
    /\ phase' = "Prepared"
    /\ UNCHANGED <<local, anchor>>

CommitLocal ==
    /\ phase = "Prepared"
    /\ pending = anchor + 1
    /\ local' = pending
    /\ phase' = "LocalCommitted"
    /\ UNCHANGED <<anchor, pending>>

FinalizeAnchor ==
    /\ phase = "LocalCommitted"
    /\ local = anchor + 1
    /\ anchor' = local
    /\ pending' = 0
    /\ phase' = "Idle"
    /\ UNCHANGED local

CrashBeforeLocal ==
    /\ phase = "Prepared"
    /\ pending' = 0
    /\ phase' = "Idle"
    /\ UNCHANGED <<local, anchor>>

CrashAfterLocal ==
    /\ phase = "LocalCommitted"
    /\ pending' = 0
    /\ phase' = "Recovery"
    /\ UNCHANGED <<local, anchor>>

RecoverOneAhead ==
    /\ phase = "Recovery"
    /\ local = anchor + 1
    /\ anchor' = local
    /\ phase' = "Idle"
    /\ UNCHANGED <<local, pending>>

\* Bounded-model terminal: Idle and fully reconciled at MaxEpoch. This is not a
\* protocol deadlock; Prepare is disabled because the epoch bound has been reached.
Terminal ==
    /\ phase = "Idle"
    /\ pending = 0
    /\ local = anchor
    /\ local = MaxEpoch

TerminalStutter ==
    /\ Terminal
    /\ UNCHANGED vars

Next ==
    Prepare \/ CommitLocal \/ FinalizeAnchor \/ CrashBeforeLocal \/
    CrashAfterLocal \/ RecoverOneAhead \/ TerminalStutter

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ local \in 0..MaxEpoch
    /\ anchor \in 0..MaxEpoch
    /\ pending \in 0..MaxEpoch
    /\ phase \in Phases

AnchorNeverAhead == anchor <= local
GapAtMostOne == local <= anchor + 1
IdleIsReconciled == phase = "Idle" => local = anchor
PreparedDoesNotAdvanceDurableState == phase = "Prepared" => local = anchor
LocalCommitIsExactlyOneAhead ==
    (phase = "LocalCommitted" \/ phase = "Recovery") => local = anchor + 1

====
