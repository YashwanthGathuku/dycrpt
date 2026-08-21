------------------------- MODULE PrekeyConsumption -------------------------
(***************************************************************************)
(* Simplified TLA+ model of one-time prekey consumption.                   *)
(*                                                                         *)
(* GOAL: One-time prekeys cannot be legitimately consumed twice.           *)
(*                                                                         *)
(* This model does NOT prove cryptographic correctness of PQXDH.           *)
(* It checks the state-machine discipline around OPK lifecycle.            *)
(***************************************************************************)

EXTENDS Integers, FiniteSets, Sequences

CONSTANTS
  PrekeyIds,          \* set of one-time prekey identifiers
  MaxConsumptions     \* usually 1 for true one-time keys

VARIABLES
  available,          \* set of prekey ids still available
  consumed,           \* function: prekey id -> number of times consumed
  session_bound       \* function: prekey id -> session id or None

TypeOK ==
  /\ available \subseteq PrekeyIds
  /\ consumed \in [PrekeyIds -> Nat]
  /\ \A id \in PrekeyIds : consumed[id] \in 0..MaxConsumptions

Init ==
  /\ available = PrekeyIds
  /\ consumed = [id \in PrekeyIds |-> 0]
  /\ session_bound = [id \in PrekeyIds |-> "none"]

\* Legitimate consumption: id must be available, then mark consumed once.
Consume(id, sid) ==
  /\ id \in available
  /\ consumed[id] = 0
  /\ available' = available \ {id}
  /\ consumed' = [consumed EXCEPT ![id] = 1]
  /\ session_bound' = [session_bound EXCEPT ![id] = sid]

\* Attacker / bug attempt to consume again — must be rejected (stutter).
DoubleConsumeAttempt(id) ==
  /\ id \notin available
  /\ UNCHANGED <<available, consumed, session_bound>>

Next ==
  \/ \E id \in PrekeyIds, sid \in {"s1", "s2", "s3"} : Consume(id, sid)
  \/ \E id \in PrekeyIds : DoubleConsumeAttempt(id)

Spec == Init /\ [][Next]_<<available, consumed, session_bound>>

(***************************************************************************)
(* INVARIANTS                                                              *)
(***************************************************************************)

\* Primary: no prekey consumed more than once.
AtMostOnce == \A id \in PrekeyIds : consumed[id] <= 1

\* Consumed keys are not still available.
ConsumedNotAvailable ==
  \A id \in PrekeyIds : consumed[id] > 0 => id \notin available

\* Available keys have zero consumptions.
AvailableUnconsumed ==
  \A id \in available : consumed[id] = 0

=============================================================================
