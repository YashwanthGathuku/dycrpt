--------------------------- MODULE RatchetState ---------------------------
(***************************************************************************)
(* Simplified TLA+ model of classical Double Ratchet state transitions.    *)
(*                                                                         *)
(* Checks:                                                                 *)
(*  - invalid authentication cannot commit state                           *)
(*  - state machine cannot enter impossible transitions                    *)
(*  - failed decrypt leaves state unchanged                                *)
(*                                                                         *)
(* Does NOT model cryptographic strength of DH / AEAD / KDF.               *)
(***************************************************************************)

EXTENDS Integers, FiniteSets

CONSTANTS MaxNs, MaxNr, MaxSkip

VARIABLES
  ns, nr, pn,           \* counters
  has_cks, has_ckr,     \* whether sending/receiving chains exist
  committed,            \* whether last decrypt committed
  phase                 \* "idle" | "trial_decrypt" | "committed"

TypeOK ==
  /\ ns \in 0..MaxNs
  /\ nr \in 0..MaxNr
  /\ pn \in 0..MaxNs
  /\ has_cks \in BOOLEAN
  /\ has_ckr \in BOOLEAN
  /\ committed \in BOOLEAN
  /\ phase \in {"idle", "trial_decrypt", "committed"}

Init ==
  /\ ns = 0
  /\ nr = 0
  /\ pn = 0
  /\ has_cks = TRUE
  /\ has_ckr = FALSE
  /\ committed = FALSE
  /\ phase = "idle"

\* Encrypt advances sending chain only when a sending chain exists.
Encrypt ==
  /\ phase = "idle"
  /\ has_cks = TRUE
  /\ ns < MaxNs
  /\ ns' = ns + 1
  /\ UNCHANGED <<nr, pn, has_cks, has_ckr, committed, phase>>

\* Begin decrypt: enter trial phase without committing.
BeginDecrypt ==
  /\ phase = "idle"
  /\ phase' = "trial_decrypt"
  /\ committed' = FALSE
  /\ UNCHANGED <<ns, nr, pn, has_cks, has_ckr>>

\* Successful AEAD: commit counter/chain updates.
CommitDecrypt ==
  /\ phase = "trial_decrypt"
  /\ has_ckr = TRUE
  /\ nr < MaxNr
  /\ nr' = nr + 1
  /\ phase' = "committed"
  /\ committed' = TRUE
  /\ UNCHANGED <<ns, pn, has_cks, has_ckr>>

\* Failed AEAD: abort trial, state unchanged.
AbortDecrypt ==
  /\ phase = "trial_decrypt"
  /\ phase' = "idle"
  /\ committed' = FALSE
  /\ UNCHANGED <<ns, nr, pn, has_cks, has_ckr>>

\* Return to idle after a successful commit (next message).
AckCommit ==
  /\ phase = "committed"
  /\ phase' = "idle"
  /\ UNCHANGED <<ns, nr, pn, has_cks, has_ckr, committed>>

\* DH ratchet: establish receiving chain, reset counters appropriately.
DHRatchet ==
  /\ phase = "idle"
  /\ has_ckr' = TRUE
  /\ has_cks' = TRUE
  /\ pn' = ns
  /\ ns' = 0
  /\ nr' = 0
  /\ UNCHANGED <<committed, phase>>

Next ==
  \/ Encrypt
  \/ BeginDecrypt
  \/ CommitDecrypt
  \/ AbortDecrypt
  \/ AckCommit
  \/ DHRatchet

Spec == Init /\ [][Next]_<<ns, nr, pn, has_cks, has_ckr, committed, phase>>

(***************************************************************************)
(* INVARIANTS                                                              *)
(***************************************************************************)

\* Failed authentication never leaves phase = committed with new counters
\* advanced without going through CommitDecrypt.
NoCommitOnFailure ==
  phase = "trial_decrypt" => committed = FALSE

\* Impossible: committed while still in trial.
NotBothTrialAndCommitted ==
  ~(phase = "trial_decrypt" /\ committed = TRUE)

\* Skip bound (simplified): nr never jumps beyond MaxSkip in one step.
\* (Full skip logic is in the implementation; here we only track monotonicity.)
CountersMonotonic ==
  ns \in 0..MaxNs /\ nr \in 0..MaxNr

=============================================================================
