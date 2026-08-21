----------------------- MODULE VoiceChatInvariants -----------------------
(***************************************************************************)
(* Top-level composition sketch of VoiceChat protocol state invariants.    *)
(*                                                                         *)
(* Instantiates the focused models:                                        *)
(*   PrekeyConsumption, RatchetState, ReplayAndIdentity                    *)
(*                                                                         *)
(* Run TLC on the individual modules with concrete finite constants.       *)
(* This file documents the intended composition and shared assumptions.    *)
(***************************************************************************)

EXTENDS Integers

\* Example finite instance parameters for TLC (override in model config).
CONSTANTS
  PrekeyIds,
  MaxConsumptions,
  MaxNs,
  MaxNr,
  MaxSkip,
  MessageIds,
  Conversations,
  Profiles

ASSUME
  /\ MaxConsumptions = 1
  /\ MaxSkip \in Nat
  /\ PrekeyIds # {}
  /\ Profiles # {}

(***************************************************************************)
(* Shared assumptions (apply to all models in this directory)              *)
(***************************************************************************)
\*
\* A1. Cryptographic primitives (X25519, ML-KEM, HKDF, AEAD, signatures)
\*     behave according to their public specifications. We do not model
\*     discrete-log or lattice hardness; we assume AEAD authenticity and
\*     signature unforgeability as black-box predicates.
\*
\* A2. The adversary controls the network (Dolev-Yao style): can drop,
\*     reorder, duplicate, and inject messages, but cannot forge AEAD tags
\*     or signatures without the corresponding keys.
\*
\* A3. Local storage either commits a full transactional update or leaves
\*     the previous committed state intact (crash = abort of open tx).
\*
\* A4. Application clocks and identifiers are unique where the model
\*     requires uniqueness (message_id uniqueness within a conversation
\*     for replay detection).
\*
\* A5. Models are finite-state approximations (bounded counters, finite
\*     sets of prekeys / messages / conversations). Unbounded real-world
\*     behavior is outside the checked fragment.
\*
\* A6. Header Encryption and Triple Ratchet are orthogonal profiles; the
\*     classical ratchet transition model is the baseline checked here.
\*

=============================================================================
