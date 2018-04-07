# Network Security and Forensics - Project
Installable linux packet
Generate random property
Generate random chain

1. (22,22) if single port
2. (22,54) for range of port
3. (0-65535) for no port
4. SADDY 
	1. -s 10.0.0.1
		a. 10.0.0.1
	2. -s 10.0.0.0/24 
		a. 10.0.0.0-10.0.0.255
5. DADDY 
	1. -d 10.0.0.1
	2. -d 10.0.0.0/24
6. SRANGE
	1. --src-range 10.0.0.1-10.0.0.1
		a. 10.0.0.1
	2. --src-range 10.0.0.0-10.0.0.255
7. DRANGE
	1. --dst-range 10.0.0.1-10.0.0.1

## Quick
### Problem
We start with two inputs
- Firewall: one sequence of rules (say, filter chain in iptables)
- Property: one rule

We are building a tool to check if the firewall satisfies the property

### Basic Ideas
Algorithm employed: *Probe*
- Probe attempts to find the witness packet. Some packet such that the firewall and the property resolve it differently.

### Recap 1
Firewall: sequence of n rules

Each rule has the form:
(**<field 1>**, **<field 2>**,...) -> **Action**
(**(10,110)**,**(90,190)**) -> **0**

Practical Example - firewall
(SRC IP=141.192.*.*, PROTO=6, DPORT=100-110) -> ACCEPT

$ iptables -A INPUT -p tcp -m iprange --src-range 141.192.0.0-141.192.255.255 --dport 100:110 -j ACCEPT

### Recap 2

A packet is specified by the value of its headers
- d-tuple of integers (source IP, destination IP...)

A packet matches a rule iff all its field values are in the corresponding range in the rule

(23,87) matches ((20,120),(80,180)) -> 1
but not ((10,110),(90,190)) -> 0

### Recap 3
Rules in a chain have priority
- The highest priority rule matched by a packet is the one applied.
- ((10,110), (90,190)) -> 0
- ((20,120),(80,180)) -> 1

decides action '0' for (23,97) because we have first-match semantics

### Example

Firewall:
10,110::90,190 -> 0
20,120::80,180 -> 1
30,130::70,170 -> 0
40,140::60,160 -> 1
1,200::1,200   -> 0

Property:
23,87::73,177  -> 0

#### Idea 1. Projection
We are looking for a packet that is resolved differently by the firewall and the property

So we need only consider packets that match the property

Projection of Rule A over Rule B.
- a rule says:
    - packets that match both Rule A and Rule B
    - get the decision of Rule A.

#### Exercise:
project
10,110::90,190 -> 0
over
23,87::73,177  -> 0

#### Idea 2. Least witness packet
We represent packets as d-tuple like (23,87)
- a tuple of values for each d fields checked

Suppose we sort packets by first field then by second field
- This is a total order. Any two packets P1 and P2 can be compared, and either P1 > P2, P1 = P2, or P1 < P2.

If there are witness packets at all, one of them is the least witness packet.

Suppose the least witness packet is (10,10)

What do we know about (9,10)

- It is not a witness packet

So firewall treats (10,10) and (9,10) differently
- Perhaps a rule is matched by (10,10) but not (9,10)
- Then the lowest f1 for this rule is f1=10
- Or perhaps a rule is matched by (9,10) but not (10,10).
- Then the highest f1 for this rule is f1=9

#### Finding least witness
Look at the edges of rules

10,110::90,190 -> 0
f1 edges: 10,111
f2 edges: 90,191

Test packets:
(10,90)
(10,191)
(111,90)
(111,191)

#### Idea 3: Improving the Search
We dont need to look at all edge packets

Why?
- we want the least witness, a packet that the firewall resolves **wrong.**

Our example property is a **discard** rule:
((23,87),(73,177) -> 0)

So we are looking for an **accepted** packet

Look for the edges but consider the decision.

((10,110),(90,190) -> 0)
This is a discard rule. We are looking for an accept packet. We go 1 past the end of each field

f1 edges: 111
f2 edges: 191

((20,120),(80,180) -> 1)
This is an accept rule. We are looking for an accept packet. We take the starting value of each field.

f1 edges: 20
f2 edges: 80

### Probe Algorithm
In order to check that firewall F satisfies property Y.
1. Project all the rules of F over Y.
2. For each field, collect a set of value

For rules with opposite decision from Y, take lower bound of interval for field.

For rules with same decision as Y, take 1 more than upper bound of interval for field.

3. Take Cartesian product of these value sets. This yields the test packets.

Firewall:
((10,110),(90,190)) -> 0
((20,120),(80,180)) -> 1
((30,130),(70,170)) -> 0
((40,140),(60,160)) -> 1
((1,200),(1,200))   -> 0

Property:
((23,87),(73,177))  -> 0

#### Step 1: Projection
Firewall:
((23,87),(90,177)) -> 0
((23,87),(80,177)) -> 1
((30,87),(73,170)) -> 0
((40,87),(73,160)) -> 1
((23,87),(73,177)) -> 0

Property:
((23,87),(73,177)) -> 0

#### Step 2: End Points
Firewall:
((23,87),(90,177)) -> 0 (agree)
**((23,87),(80,177)) -> 1**(disagree)
((30,87),(73,170)) -> 0 (agree)
**((40,87),(73,160)) -> 1** (disagree)
((23,87),(73,177)) -> 0 (agree)

Disagree End Points: {23,40,~~88~~},{73,80,~~178~~}

#### Step 3: Tests
{23,40,~~88~~}X{73,80,~~178~~}
= (23,73),(40,73),(23,80),(40,80)

((10,110),(90,190)) -> 0
((20,120),(80,180)) -> 1
((30,130),(70,170)) -> 0
((40,140),(60,160)) -> 1
((1,200),(1,200))   -> 0

returns 0,1,0,1 (not 0,0,0,0)

So some witness packets were found! Firewall has bugs.

#### Almost There!

We already did projection over the property.

What do we know about witness packets?
- Match the property
- Resolved by a rule in the firewall that disagrees with the property

#### Idea 4: Slicing!
Make it a two-way fight

Project over the property

Now bring out the rules that say different. One by one.
- Does any of those rules resolve a witness packet?

#### Implement Slicing
Look at the decision of the property. (Here, 0.)

The rules in the firewall with the same decision 0 are friend rules. The others are enemy rules

For each enemy rule, we create a slice firewall.

- The slice consists of the enemy rule, plus all the friend rules that might mask it.
- Next, we project the slice firewall over the enemy rule.

Finally, we run Probe on each slice.

#### Example
Firewall

((10,110),(90,190)) -> 0 (friend)
((20,120),(80,180)) -> 1 (enemy)
((30,130),(70,170)) -> 0 (friend)
((40,140),(60,160)) -> 1 (enemy)
((1,200),(1,200))   -> 0 (friend)

Property:
((23,87),(73,177)) -> 0

#### Making Slices
Slice on rule 2:
((10,110),(90,190)) -> 0 friend
((20,120),(80,180)) -> 1 enemy

Slice on rule 4:
((10,110),(90,190)) -> 0 friend
((30,130),(70,170)) -> 0 friend
((40,140),(60,160)) -> 1 enemy

#### Making Slices: Projection
Slice on rule 2:
((20,110),(90,180)) -> 0 friend
((20,120),(80,180)) -> 1 enemy

Slice on rule 4:
((40,110),(90,160)) -> 0 friend
((40,130),(70,160)) -> 0 friend
((40,140),(60,160)) -> 1 enemy

#### Probe: Projection
Slice on rule 2:
((23,87),(73,177)) -> 0 friend
((23,87),(73,177)) -> 1 enemy

Slice on rule 4:
((40,87),(90,160)) -> 0 friend
((40,87),(73,160)) -> 0 friend
((40,87),(73,160)) -> 1 enemy

Property:
((23,87),(73,177)) -> 0

#### Probe: End Points
**0** = Right end
**1** = Left end

Slice on rule 2:
((23,**87**),(73,**177**)) -> 0 friend
((**23**,87),(**73**,177)) -> 1 enemy

Slice on rule 4:
((40,**87**),(90,**160**)) -> 0 friend
((40,**87**),(73,**160**)) -> 0 friend
((**40**,87),(**73**,160)) -> 1 enemy

Property:
((23,87),(73,177)) -> 0

SO,

Slice on rule 2:
{23,~~88~~}X{73,~~178~~}

Slice on rule 4:
{40,~~88~~}X{73,~~161~~}

Property:
((23,87),(73,177)) -> 0

### Finally
Slice on rule 2:
(23,73)

Slice on rule 4:
(40,73)

This is a witness packet!
Proved: firewall has bugs!

### Final Version!
To check firewall F satisfies Property Y.

- Create the slice firewalls for all rules R that conflict with Y.
- For each slice,
    - Project the slice over Y.
    - For each field, collect values from the rules in the slice:
        - If last rule in slice, value = lower bound of field in rule.
        - Otherwise, value = 1 + upper board of field in rule.
    - Test packets = Cartesian product of these value sets

*Note: we dropped 161. Why?
It doesnt fall outside the property. but it does fall outside the enemy rule.*


## Slow
### Access Control: Networks
- Access is requested in a network when a packet is forwarded
    - The packet is forwarded on a particular interface, or dropped, based on features it is classified by.
    - Usually these features are fields in the header. (Source Addr, Dest Addr, Port, Echo Packet ID, and Sequence Number, Protocol...)
    - We abstract a packet as a d-tuple of integers (x1, x2, ... xd).
- The security policy is expressed by rules.
    - Each rule consists of a guard and an action.
    - We abstract the guard as a d-tuple of integer intervals ((y1, z1), (y2, z2),...(yd,zd)).
    - If a packet matches a rule, the action of the rule applies.
    - (23,127) matches ((20,120),(80,180)) -1
    - Action 1 is applied to the above packet

### Conflict
- It is possible multiple rules, with different actions, are matched by the same packet.
    - How do we decide which one is actually applied?
    - Precedence!
        - The rules are totally ordered.
        - The first matched rule resolves the packet.
    - For example, consider the policy
        - ((10, 110), (90,190)) -0
        - ((20, 120), (80,180)) -1
        - ((30, 130), (70, 170)) -0
        - ((40, 140), (60, 160)) -1
        - ((1, 200), (1, 200)) -0
    - Packet (23, 127) matches both the first and second rules.
    - It is resolved by the first fule, so the action is 0.

### Problems
- The ACL can be of length n=10^5 rules, reach with d=10 fields
- Fast algorithms are needed for:
    - Packet resolution
    - Property verification
        - A property is a rule. We want to check that, for all packets that match the property, the action of the ACL is the same as the action of the property.

### Witness Packet
- Given an ACL 'F' and a property 'Y', a witness packet is one that
    - matches 'Y'
    - is treated differently by 'F' and 'Y'

- If 'F' satisfied 'Y' ... no witness packets exist for 'F' and 'Y'.
- If there is a witness packet for 'F' and 'Y', there is a least least witness packet for 'F' and 'Y', say(a, b).
    - A packet is a finite tuple of integers.
    - Randomly order the fields (f1 more significant than f2...)
    - Total ordering!
- Probe finds the least witness packet in n^d time.
- In order to check that an ACL 'F' satisfies property 'Y',
    - Take the slices for all rules 'R' that conflict with 'Y'.
    - Project these slices over 'Y'.
    - For each slice,
        - If last rule in slice, value is lower bound of interval for field.
        - Otherwise, value is 1 more than upper bound of interval for field.
    - Test the packets in the Cartesian product of these value sets.

### Example

**ACL:**
((10,110), (90,190)) -0
**((20,120), (80,180)) -1**
((30,130), (70,170)) -0
**((40,140), (60,160)) -1**
((1,200), (1,200))   -0

**Property:**
((23,87), (73,177)) -0

**Slices:**
1. ((23,87), (90,177)) -0
2. **((23,87), (80,177)) -1**
3. ((40,87), (90,160)) -0
4. ((40,87), (73,160)) -0
5. **((40,87), (73,160)) -1**

((23,87), (90,177)) -0
**((23,87), (80,177)) -1**
f1: {23,**88**},f2:{80,**178**}

First slice, test packets:
{23} x {80} i.e. (23,80)

((40,87), (90,160)) -0
((40,87), (73,160)) -0
**((40,87), (73,160)) -1**
f1: {40,**88**},f2:{73,**161**}

Second slice, test packets:
{40} x {73} i.e. (40,73)

### Always
**Theorem II:**

- F satisfies iff none of the projected slices have a witness packet.

**Theorem III:**

- If a slice has a witness packet, one of the packets in the Cartesian product of collected values is a witness packet.

### Complexity
- The rate-determining step of Probe?
    - testing all the packets from the Cartesian product of field values
- How many packets?
- From each rule, we take a single value for each field
    - n^d time per slice; n^d+1 time overall.
    - Still not good enough...

### Probe: Proofs
**Theorem II:**
- F satisfies Y iff none of the projected slices have a witness packet.

**Theorem III:**
- If a slice has a witness packet, one of the packets in the Cartesian product of collected values is a witness packet.

**Description from H.B.**
"Write a Linux tool that takes as input a firewall (or picks up the machine's iptables filter chains), 
and a property (which is ONE iptables rule), and check - using the algorithm given in the slides - 
whether the firewall satisfies the property. 

In other words, if the property says “accept the packets matching this predicate”, all those packets
are accepted by the firewall. If it says, “reject …” all those packets are discarded by the firewall.
(You can be smart and ask the user if filtered packets count as discard, or only dropped packets.)

Ideally, the tool should be available as a package. It would be even better if you could set up a 
repo so ubuntu users can install it with apt-get. Performance (speed, memory) matters, but any
language is fine."
