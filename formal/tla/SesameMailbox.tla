---- MODULE SesameMailbox ----
EXTENDS Naturals, Sequences, TLC

CONSTANTS Devices, MaxLoop

VARIABLES inbox, sent, receipts, retries, loop

TypeOK ==
  /\ inbox \in [Devices -> Seq(STRING)]
  /\ sent \in Nat
  /\ receipts \in Nat
  /\ retries \in Nat
  /\ loop \in 0..MaxLoop

Init ==
  /\ inbox = [d \in Devices |-> << >>]
  /\ sent = 0
  /\ receipts = 0
  /\ retries = 0
  /\ loop = 0

Send(d) ==
  /\ loop < MaxLoop
  /\ inbox' = [inbox EXCEPT ![d] = Append(@, "enc")]
  /\ sent' = sent + 1
  /\ loop' = loop + 1
  /\ UNCHANGED <<receipts, retries>>

RecvOk(d) ==
  /\ Len(inbox[d]) > 0
  /\ Head(inbox[d]) = "enc"
  /\ inbox' = [inbox EXCEPT ![d] = Tail(@)]
  /\ receipts' = receipts + 1
  /\ UNCHANGED <<sent, retries, loop>>

RecvRetry(d) ==
  /\ Len(inbox[d]) > 0
  /\ inbox' = [inbox EXCEPT ![d] = Tail(@)]
  /\ retries' = retries + 1
  /\ UNCHANGED <<sent, receipts, loop>>

Idle ==
  /\ loop = MaxLoop
  /\ \A d \in Devices : inbox[d] = << >>
  /\ UNCHANGED <<inbox, sent, receipts, retries, loop>>

Next == Idle \/ \E d \in Devices : Send(d) \/ RecvOk(d) \/ RecvRetry(d)

Spec == Init /\ [][Next]_<<inbox, sent, receipts, retries, loop>>

ReceiptsBounded == receipts <= sent
LoopsBounded == loop <= MaxLoop
====
