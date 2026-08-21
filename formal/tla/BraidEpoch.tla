---- MODULE BraidEpoch ----
EXTENDS Naturals, TLC

VARIABLES epochA, epochB, keysA, keysB

Init ==
  /\ epochA = 1
  /\ epochB = 1
  /\ keysA = {}
  /\ keysB = {}

AdvanceA ==
  /\ epochA <= epochB
  /\ epochA < 4
  /\ epochA' = epochA + 1
  /\ keysA' = keysA \union {epochA}
  /\ UNCHANGED <<epochB, keysB>>

AdvanceB ==
  /\ epochB <= epochA
  /\ epochB < 4
  /\ epochB' = epochB + 1
  /\ keysB' = keysB \union {epochB}
  /\ UNCHANGED <<epochA, keysA>>

Agree ==
  /\ epochA = epochB
  /\ keysA' = keysA \union {epochA}
  /\ keysB' = keysB \union {epochB}
  /\ UNCHANGED <<epochA, epochB>>

Next == AdvanceA \/ AdvanceB \/ Agree

Spec == Init /\ [][Next]_<<epochA, epochB, keysA, keysB>>

EpochsClose == epochA <= epochB + 1 /\ epochB <= epochA + 1
====
