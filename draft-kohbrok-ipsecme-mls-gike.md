---
title: "MLS for IPsec Group Key Exchange"
abbrev: "MLS-GIKE"
category: info

docname: draft-kohbrok-ipsecme-mls-gike-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "IP Security Maintenance and Extensions"
keyword:
 - encryption
 - group key exchange
venue:
  group: "IP Security Maintenance and Extensions"
  type: "Working Group"
  mail: "ipsec@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ipsec/"
  github: "kkohbrok/draft-kohbrok-ipsecme-mls-gike"
  latest: "https://kkohbrok.github.io/draft-kohbrok-ipsecme-mls-gike/draft-kohbrok-ipsecme-mls-gike.html"

author:
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad@ratchet.ing

normative:
  RFC7296:
  RFC9420:
  RFC9838:
  I-D.ietf-mls-ratchet-tree-options:

informative:
  RFC4301:
  RFC9750:

...

--- abstract

This document describes a profile that uses the Messaging Layer Security (MLS) protocol as the group key-management substrate for Group Key Management using IKEv2 (G-IKEv2).
The intent is to preserve the operational model of G-IKEv2, including IKEv2 transport, GSA policy distribution, a central GCKS, and the IPsec ESP data plane, while replacing GDOI-style group key distribution with an MLS group.
The resulting design can be read as G-IKEv2 where MLS produces the per-epoch group secret used to key the IPsec ESP Data-Security SA.


--- middle

# Introduction

G-IKEv2 {{RFC9838}} defines group key management for IPsec group traffic using IKEv2 {{RFC7296}} exchanges between Group Members (GMs) and a Group Controller/Key Server (GCKS).
The GCKS distributes group policy in a Group Security Association (GSA) payload and distributes traffic keys in a Key Download (KD) payload.
This gives operators a familiar centralized control point for authorization, policy, rekey, and member exclusion.

MLS {{RFC9420}} is a group key agreement protocol that maintains a group state across epochs.
Members authenticate and agree on each epoch by processing MLS handshake messages.
Applications can then derive key material from the MLS exporter defined in Section 8.5 of {{RFC9420}}.

This document proposes using MLS to replace the KEK, TEK, and Logical Key Hierarchy machinery inherited by G-IKEv2 from GDOI-style group key distribution.
IKEv2 remains the authenticated unicast transport between each GM and the GCKS.
The GSA payload remains the source of IPsec policy, traffic selectors, transforms, Sender-ID parameters, activation delay, and deactivation delay.
The ESP data plane and the SPD/SAD model remain the IPsec data plane described by {{RFC4301}}.

The main change is that traffic keys are no longer downloaded by the GCKS in KD Group Key Bags.
Instead, every GM that is an MLS member derives the Data-Security SA keys for the current MLS epoch with the MLS exporter.
The GCKS does not hold an MLS member leaf and therefore does not derive the exported traffic keys.
The existing KD payload is still reused for GCKS-originated MLS objects and Sender-ID material.
GM-originated MLS objects use the existing Notify payload with profile-defined notification data.
This profile therefore does not allocate a separate IKE payload type for every MLS structure it carries.

This document is descriptive and is not a complete normative specification.
Several details needed for interoperability are intentionally stated as design constraints or open issues.
This document leaves several optimizations and deployment variants as TODOs or open questions.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

GCKS:
: Group Controller/Key Server, as defined by G-IKEv2.

GM:
: Group Member.

Candidate GM:
: A device that has authenticated to the GCKS but has not yet entered the MLS group.

Founding GM:
: The first GM in an MLS group created for a G-IKEv2 group.

DS:
: MLS Delivery Service.

AS:
: MLS Authentication Service.

Data-Security SA:
: The ESP SA used to protect group data traffic.

External sender:
: An entity authorized by the MLS `external_senders` GroupContext extension to send external Proposals to the group.

Path refresh:
: An empty MLS Commit with an UpdatePath that refreshes the committer's leaf and direct path.

PartialGroupInfo:
: The structure defined by {{I-D.ietf-mls-ratchet-tree-options}} that lets a committer upload only the parts of GroupInfo the DS cannot reconstruct from public handshakes.

# MLS Concepts Used by This Design

This section summarizes the MLS concepts needed to read the rest of the document.

An MLS group has a group state that advances through monotonically increasing epochs.
Each epoch represents a specific membership, public ratchet tree, transcript state, and set of derived secrets.
Only one Commit is accepted for a given epoch transition, so the Delivery Service (DS) normally provides ordering for handshake messages.
Section 5.2 of {{RFC9750}} discusses this DS sequencing role.

Each MLS member occupies one leaf in a public ratchet tree.
The ratchet tree is the data structure MLS uses to update group secrets efficiently when members are added, removed, or refreshed.
This draft maps one IPsec GM to one MLS leaf.

A KeyPackage is the object that a prospective member publishes so that an existing member can add it to a group.
See Section 10 of {{RFC9420}}.
The KeyPackage contains the protocol version, cipher suite, an init key used to encrypt a Welcome, and a LeafNode carrying the member credential and public encryption key.
In this draft, a Candidate GM sends a KeyPackage to the GCKS during registration.

MLS represents pending group changes as Proposals and applies them through Commits.
The proposal types relevant to this draft are Add, Remove, and the empty Commit with an UpdatePath described in Section 12.4 of {{RFC9420}}.
An Add proposal introduces a KeyPackage into the group.
A Remove proposal removes an existing leaf.
An empty Commit with an UpdatePath refreshes the committer's leaf and direct path without proposing an application-visible membership change.

A Welcome message carries the encrypted information a newly added member needs to join the epoch created by an Add Commit.
See Section 12.4.3.1 of {{RFC9420}}.
The Welcome contains an encrypted GroupInfo object.
The GroupInfo is a signed snapshot of the epoch, including the GroupContext, the signer, and the confirmation tag.
The joining client also needs the public ratchet tree before it can process the Welcome.
RFC 9420 allows this tree to be carried in the Welcome as a `ratchet_tree` extension or to be provided by another channel, such as a caching service on the DS.
See Sections 12.4.3.1 and 12.4.3.3 of {{RFC9420}}.
This document uses the second option: the GCKS tracks the tree from MLS PublicMessages and sends it to the joining GM outside the Welcome.

MLS allows an entity outside the group to send certain Proposals if the group has configured that entity in the `external_senders` GroupContext extension.
See Section 12.1.8 of {{RFC9420}}.
This draft uses that mechanism to let the GCKS propose Add and Remove operations without making the GCKS an MLS member.
Because an external sender is not a group member, it can propose changes but cannot create a regular Commit for the group.

MLS distinguishes delivery from authentication.
The MLS architecture describes a Delivery Service that orders and relays messages, and an Authentication Service that is responsible for member identities and credentials.
See {{RFC9750}}.
In this profile, the GCKS acts as DS, AS, and MLS external sender.
OPEN QUESTION: What protocol changes are required to split the DS, AS, and external-sender roles across separate components?

MLS exposes an exporter that derives application key material from the epoch's `exporter_secret`.
See Section 8.5 of {{RFC9420}}.
This draft uses that exporter to derive IPsec Data-Security SA keying material.
MLS is not used to carry IPsec packets or application data in this design.

# Scope

This document describes a deliberately narrow profile.
Commit generation, candidate delivery, founder upload, and member upload use per-member unicast IKE SAs.
Ordered Commit fan-out can use either per-member `GSA_INBAND_REKEY` or multicast `GSA_REKEY`.
If multicast `GSA_REKEY` is used and the deployment needs future control-plane messages hidden from removed members, the G-IKEv2 Rekey SA uses LKH as described in Appendix A of {{RFC9838}}.

The GCKS is the only entity authorized to propose structural membership changes.
Members do not propose Add or Remove operations for other members.
Members can refresh their own MLS contribution by sending an empty Commit with an UpdatePath.

New members join through Add plus Welcome.
This profile does not define joining through External Commit, as defined in Section 12.4.3.2 of {{RFC9420}}.
OPEN QUESTION: Should External Commit be specified for joining, resynchronization, or both, and what GCKS validation is required?

MLS membership is distinct from data-plane sender authorization.
A GM that intends to send ESP traffic on a Data-Security SA indicates that role with the `GROUP_SENDER` notification defined in Section 4.7.4 of {{RFC9838}}.
A GM that does not request sender authorization can still join the MLS group and derive the epoch's Data-Security SA keys, but it is not authorized to emit ESP traffic for that SA.
This draft keeps the Sender-ID machinery of G-IKEv2 for authorized senders using counter-based ESP modes.
This is G-IKEv2 policy authorization and nonce-space partitioning, not per-sender traffic-key separation.

The GCKS is a single instance for a group.
GCKS replication and failover are out of scope.

The group uses one current ESP Data-Security SA per MLS epoch for the relevant group traffic selectors.
The previous epoch's SA can overlap during rollover according to the GWP_ATD and GWP_DTD policy attributes.
This profile does not define AH Data-Security SAs.
TODO: Decide whether AH Data-Security SAs need explicit support or explicit exclusion.

# Design Overview

The design keeps the G-IKEv2 policy plane and replaces the key-distribution plane.
The GSA payload defined in Section 4.4 of {{RFC9838}} continues to describe the Data-Security SA policy, traffic selectors, transforms, Sender-ID parameters, and rollover timing.
The KD payload defined in Section 4.5 of {{RFC9838}} is no longer used to carry TEK or KEK key material.
This profile reuses KD bags for two GCKS-originated purposes: KD Member Key Bags carry `GM_SENDER_ID` attributes and member-scoped MLS objects, and KD Group Key Bags carry group-scoped MLS objects associated with an epoch-bound Data-Security SA SPI.
This use of KD for MLS objects carries no `SA_KEY`, `WRAP_KEY`, or `AUTH_KEY` material.
MLS objects that flow from a GM to the GCKS use the Notify payload instead of KD.

The GCKS creates a per-group MLS external-sender signing key.
The public key and credential for that signing key are installed in the MLS `external_senders` GroupContext extension.
Members use this extension to verify that Add and Remove Proposals originated from the GCKS.

The GCKS is not an MLS member.
It does not hold an MLS leaf private key, path secrets, epoch secrets, or exporter output.
It tracks the public ratchet tree and GroupInfo state needed to act as a DS.
Because it has no MLS epoch secrets, it can perform public checks but cannot verify MLS membership MACs or confirmation tags.

A designated GM commits GCKS-authored external Proposals.
The designated committer is the lowest non-blank leaf that is not the leaf being removed.
The GCKS can retry with the next non-blank leaf if the designated committer is unreachable or refuses to commit.

All MLS Proposals and Commits in this profile are sent as MLS PublicMessages.
This lets the GCKS reconstruct the public tree from the handshake stream.
This is the `distributionService` ratchet-tree representation described in Section 3 of {{I-D.ietf-mls-ratchet-tree-options}}.
The PublicMessages are still protected on the wire by the IKEv2 `SK{}` envelope.

Committers upload `PartialGroupInfo` as defined in Section 4 of {{I-D.ietf-mls-ratchet-tree-options}}.
The upload carries the GroupInfo signature and non-`ratchet_tree` GroupInfo extensions.
The GCKS reconstructs the rest of the GroupInfo from its tracked public state and the observed Commit.
The GCKS also maintains the public ratchet tree locally and sends it to new members in the Welcome exchange.
The first founder upload is the only exception to the reconstruction rule, because there is no previous epoch from which the GCKS can reconstruct the tree.

# Mapping from G-IKEv2 to MLS-GIKE

The following table summarizes the intended mapping.

| G-IKEv2 concept | MLS-GIKE concept |
|---|---|
| GCKS | GCKS plus MLS DS, AS, and external sender. |
| GM | MLS group member with one leaf in the MLS tree. |
| Group ID (`IDg`) | MLS `group_id`, bound to the G-IKEv2 group. |
| GSA payload | Reused for IPsec policy and Data-Security SA parameters. |
| KD Group Key Bag | Retained for GCKS-to-GM group-scoped MLS objects, but not for SA key delivery. |
| KD Member Key Bag | Retained for `GM_SENDER_ID` and GCKS-to-GM member-scoped MLS objects. |
| Notify payload | Used for MLS objects that are not KD downloads. |
| Rekey SA | Optional. Protects multicast `GSA_REKEY` delivery. Not used to derive or wrap ESP Data-Security SA keys. |
| KEK for ESP Data-Security SA key delivery | Not used. |
| TEK key material | Derived from the MLS exporter. |
| `GSA_REKEY` | Optional multicast fan-out for ordered MLS control material. |
| `GSA_AUTH` and `GSA_REGISTRATION` | Reused with `N(MLS_OBJECT)` in requests and KD-carried MLS objects in responses. |
| `GSA_MLS_REQUEST_COMMIT` | New GCKS-to-GM exchange asking a designated GM to commit a GCKS-authored Proposal. |
| `GSA_INBAND_REKEY` | Reused for GCKS-to-GM unicast delivery of epoch-bound GSA updates and related MLS objects. |
| Member exclusion | GCKS sends an external Remove Proposal. A designated GM commits it. |
| Sender-ID | Reused for counter-based ESP nonce partitioning. |
| GWP_ATD and GWP_DTD | Reused to manage Data-Security SA rollover. |

# Group Creation

MLS groups are created by an initial member.
See Section 11 of {{RFC9420}}.
Because the GCKS is not an MLS member, the first GM to join a configured but empty G-IKEv2 group becomes the MLS founder.

When the GCKS is configured for a new group, it generates a per-group MLS external-sender signing key pair.
The public key and credential for that pair are placed in an `mls_group_template` object carried in KD.
The template also carries the MLS cipher suite, the MLS group identifier, required capabilities, and any other GroupContext extensions required by GCKS policy.

The first Candidate GM authenticates to the GCKS with the MLS-GIKE variant of `GSA_AUTH`.
The GCKS returns the normal GSA policy and the `mls_group_template` object.
The founder creates a one-member MLS group using the template values.
The founder then uses `GIKE_MLS_UPLOAD` to send `N(MLS_OBJECT)` notifications carrying an `mls_group_info` object containing a full `GroupInfo` and an `mls_ratchet_tree` object containing the initial public ratchet tree to the GCKS.

The GCKS verifies that the founder's GroupContext matches the template, verifies that the uploaded tree hash matches the GroupInfo tree hash, and verifies the founder's GroupInfo signature against the founder's LeafNode signing key.
The GCKS cannot verify the MLS confirmation tag.
The uploaded GroupInfo becomes the GCKS baseline for public tracked state.

# Registration

A Candidate GM authenticates to the GCKS using the same IKEv2 authentication machinery used by G-IKEv2.
The request carries `IDg`, an `N(MLS_OBJECT)` notification containing an `mls_key_package` object, and a `GROUP_SENDER` notification only if the GM intends to send Data-Security SA traffic.

The `mls_key_package` object contains an MLS KeyPackage.
The KeyPackage identifies the MLS protocol version and cipher suite supported for this join.
If the GCKS cannot accept those MLS parameters, it rejects the exchange with `NO_PROPOSAL_CHOSEN`.
The identity in the KeyPackage LeafNode credential MUST be bound to the IKE identity authenticated in the exchange.
For example, a basic credential identity can equal `IDi`, or an X.509 credential can contain a subjectAltName matching `IDi`.

The GCKS response carries a GSA payload that describes policy but is not installable as a Data-Security SA.
If the GM requested sender authorization and the Data-Security SA uses a counter-based ESP mode, the response also carries a KD Member Key Bag containing one or more `GM_SENDER_ID` attributes as specified by Section 4.5.3.3 of {{RFC9838}}.
The response does not carry MLS group state unless the group is empty and the candidate is becoming the founder.
The candidate is not yet in an MLS epoch from which it can derive traffic keys.
Any SPI carried in that GSA is tentative until the GSA for the accepted MLS epoch is delivered.
The installable GSA is sent later with `mls_welcome` to the candidate and with the ordered `mls_commit` to existing members.
If the installable GSA differs from the registration GSA, the candidate validates it again during Welcome processing.
This duplicate GSA transmission gives the candidate an early policy check while keeping SAD installation tied to the accepted MLS epoch.

# Adding a Member

After registration, a Candidate GM has an IKE SA to the GCKS and has received the initial non-installable GSA policy, but it is not yet an MLS member.
The GCKS drives the join by sending an external Add Proposal to a designated committer.

~~~ aasvg
Candidate        GCKS        Designated GM D                         Existing GMs
    |             |                 |                                      |
    | GSA_AUTH {N(MLS_OBJECT: mls_key_package)}                            |
    +------------>|                 |                                      |
    |             |                 |                                      |
    | GSA(policy), optional KD      |                                      |
    |<------------+                 |                                      |
    |             |                 |                                      |
    |             | GSA_MLS_REQUEST_COMMIT {N(MLS_OBJECT: mls_proposal)}   |
    |             +---------------->|                                      |
    |             |                 |                                      |
    |             | <empty response> |                                    |
    |             |<----------------+                                      |
    |             |                 |                                      |
    |             | GIKE_MLS_UPLOAD {N(MLS_OBJECT: mls_commit),           |
    |             |                  N(MLS_OBJECT: mls_welcome),          |
    |             |                  N(MLS_OBJECT: mls_partial_group_info)}|
    |             |<----------------+                                      |
    |             |                 |                                      |
    |             | <empty or error> |                                    |
    |             +---------------->|                                      |
    |             |                 |                                      |
    | GSA_INBAND_REKEY {GSA(epoch), KD(mls_welcome, mls_ratchet_tree)}     |
    |<------------+                 |                                      |
    |             |                 |                                      |
    |             | GSA_INBAND_REKEY {GSA(epoch), KD(mls_proposal,        |
    |             |                    mls_commit)}                       |
    |             +------------------------------------------------------->|
    |             |                 |                                      |
~~~
{: #fig-add-member-flow title="Adding a Member"}

In multicast fan-out mode, the final per-member `GSA_INBAND_REKEY` exchanges to existing GMs are replaced by one `GSA_REKEY` to the GMs that share the Rekey SA.

The GCKS signs the Add Proposal with its MLS external-sender key.
The Proposal is carried in `GSA_MLS_REQUEST_COMMIT`.
The designated committer verifies the Proposal using the `external_senders` extension in its current MLS group state.
It creates a Commit that references the Proposal, includes an UpdatePath, creates a Welcome for the candidate, signs a GroupInfo for the new epoch without a `ratchet_tree` extension, and uploads the Commit, Welcome, and PartialGroupInfo to the GCKS as `N(MLS_OBJECT)` notifications in `GIKE_MLS_UPLOAD`.

The designated committer treats the new epoch as tentative until the GCKS orders the Commit.
If the GCKS rejects the Commit, the committer discards the tentative epoch.
If the GCKS accepts it, the GCKS allocates a fresh Data-Security SA SPI, stores the public state, sends the Welcome, GSA, and GCKS-tracked ratchet tree to the candidate using `GSA_INBAND_REKEY`, and fans the GSA, Proposal, and Commit to existing GMs including the committer using `GSA_INBAND_REKEY`.
If multicast fan-out is enabled, the GCKS can instead send the GSA, Proposal, and Commit to existing GMs using `GSA_REKEY`.
The Welcome, ratchet tree, Proposal, and Commit are carried as MLS objects inside KD.
The GSA sent at this point is the GSA that GMs use for SAD installation after MLS acceptance.

The Proposal is included in the fan-out because the Commit references the Proposal by hash.
Receivers need the referenced Proposal object in order to validate and apply the Commit.
See Section 12.4 of {{RFC9420}}.

The Candidate GM decrypts the Welcome using the init key corresponding to the KeyPackage sent during registration.
It validates the GroupInfo and verifies that the supplied ratchet tree has the tree hash committed by the GroupInfo.
It then derives the ESP keys for the new Data-Security SA.

# Removing a Member

The GCKS removes a member by sending an external Remove Proposal to a designated committer.
The designated committer is the lowest non-blank leaf that is not the leaf being removed.
The Proposal is carried in `GSA_MLS_REQUEST_COMMIT`.
The designated committer creates a Commit that references the Remove Proposal and uploads the Commit plus PartialGroupInfo to the GCKS as `N(MLS_OBJECT)` notifications in `GIKE_MLS_UPLOAD`.

If the GCKS accepts the public state transition, it allocates a fresh Data-Security SA SPI and fans `GSA` plus KD-carried `mls_proposal` and `mls_commit` objects to the remaining GMs using `GSA_INBAND_REKEY` or `GSA_REKEY`.
The removed GM does not receive any new Data-Security SA keying material.
If multicast `GSA_REKEY` is used, the removed GM can receive the fresh GSA policy and MLS control material, but cannot derive the new MLS epoch secret or the new ESP key.
In unicast fan-out mode, if the removed GM's IKE SA is still available, the GCKS sends the `mls_proposal` and `mls_commit` objects without the fresh GSA to the removed GM so it has an authenticated indication that it has been removed.
The removed GM can verify the Remove proposal and Commit structure but cannot derive the new epoch.
If that delivery is not possible, the GCKS needs another authenticated indication, such as an IKE Delete or Notify, before it accepts further group traffic from that GM.
The GCKS then tears down the IKE SA to the removed GM if appropriate.

There is no separate KEK-then-TEK rekey step.
The MLS Remove Commit creates the new epoch, and the removed member cannot compute the new epoch secret.
The removed member still knows the previous epoch's ESP key and any Sender-ID values it was assigned.
While remaining members continue to accept packets protected under the previous Data-Security SA during the GWP_DTD overlap, there is a residual acceptance window for packets from the removed member.
This profile identifies that rollover window.
It does not specify tighter exclusion behavior.

# Member-Initiated Path Refresh

A GM can refresh its MLS contribution by creating an empty Commit with an UpdatePath.
This is the MLS mechanism used here for member-initiated post-compromise recovery.
The Commit contains no Proposals.

The GM sends the Commit and PartialGroupInfo to the GCKS using `GIKE_MLS_UPLOAD` with `N(MLS_OBJECT)` notifications.
If the Commit's epoch matches the GCKS current epoch, the GCKS orders it, allocates a fresh Data-Security SA SPI, and fans `GSA` plus a KD-carried `mls_commit` object to every GM including the author using `GSA_INBAND_REKEY`.
If multicast fan-out is enabled, the GCKS can instead fan the ordered Commit out using `GSA_REKEY`.
The author applies its own Commit only when it receives the GCKS-ordered copy.

If another Commit has already been accepted for that epoch, the GCKS rejects the later Commit with `MLS_COMMIT_REJECTED` and a stale-epoch indication.
The member then processes the winning Commit through normal fan-out and can retry the refresh in the new epoch.

# ESP Key Derivation and Rollover

For each accepted MLS epoch, every GM derives the keying material for the current Data-Security SA using the MLS exporter.
The provisional exporter label is:

~~~
MLS-GIKE ESP key
~~~

The exporter context includes a domain separator and the SPI from the GSA:

~~~
context = "ESP" || SPI
~~~

The string `"ESP"` is the three-octet ASCII string `0x45 0x53 0x50`.
The SPI is the four-octet ESP SPI from the GSA encoded in network byte order.
The context is not NUL-terminated.

The exported value is split into ESP encryption and integrity key material using the same left-to-right convention used for Data-Security SAs in Section 3.4 of {{RFC9838}}.
For AEAD ESP transforms, the length and split rules are the AEAD-specific rules for the selected transform.

The GCKS allocates a fresh Data-Security SA SPI for every accepted MLS epoch.
This is necessary because two exporter outputs can be valid during GWP_ATD and GWP_DTD overlap.
Receivers need the SPI to distinguish packets protected with the old epoch key from packets protected with the new epoch key.

For counter-based ESP modes, this draft inherits the Sender-ID rules from Section 2.5 of {{RFC9838}}.
The GCKS includes `GWP_SENDER_ID_BITS` when required by Section 4.4.3.1.2 of {{RFC9838}}.
A GM authorized as a receiver installs the Data-Security SA inbound.
A GM authorized as a sender installs the Data-Security SA outbound and uses its assigned Sender-ID bits when constructing ESP nonces.
The GCKS allocates `GM_SENDER_ID` values in the KD Member Key Bag for authorized senders when required by Section 4.5.3.3 of {{RFC9838}}.
A GM that is not authorized as a sender MUST NOT install the Data-Security SA outbound.
Implicit-IV ESP transforms remain prohibited for multi-sender Data-Security SAs as described in Section 2.7 of {{RFC9838}}.

# Optional Multicast Fan-Out with GSA_REKEY

Deployments of this profile MAY use `GSA_REKEY` for multicast delivery of ordered MLS control material to GMs that share a G-IKEv2 Rekey SA.
When this mode is enabled, MLS remains the only source of Data-Security SA traffic keys.
The GCKS MUST NOT distribute ESP Data-Security SA key material in `GSA_REKEY`.
Any KD Group Key Bag associated with an ESP Data-Security SA carries only MLS objects and no `SA_KEY`, `WRAP_KEY`, or `AUTH_KEY` material for that Data-Security SA.

The G-IKEv2 Rekey SA is used only to protect and authenticate multicast control-plane delivery.
The Rekey SA MAY be managed using the LKH mechanism described in Appendix A of {{RFC9838}}.
When LKH is not used, a removed GM that still knows the current Rekey SA key can read later `GSA_REKEY` messages protected by that Rekey SA.
Deployments that cannot accept this exposure use per-member `GSA_INBAND_REKEY` after removals or rotate the Rekey SA using a mechanism that excludes the removed GM.
If a deployment requires future multicast control-plane messages to be hidden from a removed GM, the GCKS MUST rotate the Rekey SA using LKH or another specified broadcast-encryption mechanism.

Ordered Commit fan-out can use the following `GSA_REKEY` shape:

~~~
GSA_REKEY {
  GSA(epoch),
  KD Group Key Bag for ESP SPI {
    MLS_OBJECT(mls_proposal),
    MLS_OBJECT(mls_commit)
  },
  [AUTH]
}
~~~

A removal that also rotates the Rekey SA can use the following shape:

~~~
GSA_REKEY {
  GSA(epoch),
  GSA(new Rekey SA),
  KD Group Key Bag for ESP SPI {
    MLS_OBJECT(mls_proposal),
    MLS_OBJECT(mls_commit)
  },
  KD(<LKH-wrapped Rekey SA material>),
  [AUTH]
}
~~~

The KD material for the new Rekey SA is wrapped according to LKH so that only remaining GMs recover the new Rekey SA key.

The removed GM can receive and parse this `GSA_REKEY` if it is protected by the old Rekey SA.
This does not give it the new Data-Security SA key, because that key is derived from the MLS epoch created by the Remove Commit.
If LKH excludes the removed GM from the new Rekey SA, the removed GM cannot decrypt later `GSA_REKEY` messages protected by that new Rekey SA.

The designated MLS committer never provides the GCKS with a Rekey SA key or a Data-Security SA key.
The committer provides only MLS Commit material.
The GCKS remains responsible for Rekey SA key generation and any LKH state.

# MLS Object Carriers and Exchanges

This profile does not define a separate IKEv2 payload type for each MLS object.
GCKS-to-GM MLS objects that are delivered as part of policy or epoch-bound state use the KD payload defined in Section 4.5 of {{RFC9838}}.
MLS objects that are not KD downloads use the Notify payload defined in Section 3.10 of {{RFC7296}}.
Both carriers use the same object wrapper.
The wrapper contains an object-type discriminator and an opaque object:

~~~
enum {
  mls_key_package(1),
  mls_group_info(2),
  mls_partial_group_info(3),
  mls_group_template(4),
  mls_proposal(5),
  mls_commit(6),
  mls_welcome(7),
  mls_ratchet_tree(8),
  (65535)
} MlsGikeObjectType;

struct {
  MlsGikeObjectType object_type;
  opaque object<V>;
} MlsGikeObject;
~~~

For KD, this profile defines a multi-valued `MLS_OBJECT` attribute for both the Group Key Bag and Member Key Bag registries.
Each attribute value contains one `MlsGikeObject`.
KD-carried `MLS_OBJECT` attributes MUST appear only in messages sent by the GCKS.
Group Key Bags carry group-scoped MLS objects associated with an epoch-bound Data-Security SA SPI, such as Commit fan-out paired with a fresh GSA.
Member Key Bags carry GCKS-originated member-scoped objects and objects that are not associated with a Data-Security SA SPI, such as Welcomes, founder bootstrap state, ratchet trees, and removal notices sent without a fresh GSA.
This use of KD for MLS objects carries no `SA_KEY`, `WRAP_KEY`, or `AUTH_KEY` material.

The bag type is semantically significant.
A receiver MUST treat an `MLS_OBJECT` in a Group Key Bag as bound to the Data-Security SA identified by the Group Key Bag Protocol and SPI fields.
A receiver MUST treat an `MLS_OBJECT` in a Member Key Bag as scoped to the authenticated peer and current G-IKEv2 group context, not to a Data-Security SA SPI.
An implementation MUST reject an `MLS_OBJECT` that appears in a bag type other than the one specified for that use.

For Notify, this profile defines an `MLS_OBJECT` Notify Message Status Type.
The Notification Data contains one `MlsGikeObject`.
Notify-carried `MLS_OBJECT` values are used for GM-to-GCKS uploads and for `GSA_MLS_REQUEST_COMMIT`.

| MLS object use | Carrier |
|---|---|
| Candidate request carrying `mls_key_package` | `N(MLS_OBJECT)` |
| Founder response carrying `mls_group_template` | KD Member Key Bag |
| Founder upload carrying `mls_group_info` and `mls_ratchet_tree` | `N(MLS_OBJECT)` |
| Commit request carrying `mls_proposal` to a designated committer | `N(MLS_OBJECT)` |
| Designated-committer upload carrying `mls_commit`, optional `mls_welcome`, and `mls_partial_group_info` | `N(MLS_OBJECT)` |
| Welcome delivery carrying `mls_welcome` and `mls_ratchet_tree` to the candidate | KD Member Key Bag |
| Existing-member fan-out carrying `mls_proposal` and `mls_commit` with the epoch-bound GSA | KD Group Key Bag |
| Removal notice carrying `mls_proposal` and `mls_commit` without a fresh GSA | KD Member Key Bag |
| Member path-refresh upload carrying `mls_commit` and `mls_partial_group_info` | `N(MLS_OBJECT)` |
| GCKS fan-out of an ordered path-refresh `mls_commit` with the epoch-bound GSA | KD Group Key Bag |

`mls_key_package` contains an MLS KeyPackage and an explicit MLS protocol version.
The IKE layer treats the KeyPackage as opaque except for policy checks needed by the GCKS.

`mls_group_template` contains the values needed by the first GM to create the initial MLS group.
It is not a GroupInfo.

`mls_group_info` contains a full MLS GroupInfo.
It is used only on the founder bootstrap path and does not carry the MLS `ratchet_tree` GroupInfo extension.

`mls_partial_group_info` contains the PartialGroupInfo structure from Section 4 of {{I-D.ietf-mls-ratchet-tree-options}}.
It is used after every Commit-driven epoch transition.
Its `ratchet_tree_presence` field is `no_ratchet_tree`, because this profile does not carry the `ratchet_tree` extension in GroupInfo objects.

`mls_proposal` contains an MLS PublicMessage containing a Proposal from the GCKS external sender.
This profile uses it only for Add and Remove Proposals.

`mls_commit` contains an MLS PublicMessage containing a Commit.
If the Commit references a GCKS-authored Proposal, the referenced Proposal is delivered with it unless the receiver already has it.

`mls_welcome` contains an MLS Welcome.
The Welcome's encrypted GroupInfo does not contain a `ratchet_tree` extension in this profile.

`mls_ratchet_tree` contains the public ratchet tree vector defined in Section 12.4.3.3 of {{RFC9420}}.
The founder sends it to the GCKS during bootstrap, and the GCKS sends it to a newly added GM alongside the Welcome.
The recipient verifies the tree against the `tree_hash` in the relevant GroupInfo before using it.

`GSA_AUTH` is reused as the initial G-IKEv2 registration exchange with an `N(MLS_OBJECT)` notification carrying an `mls_key_package` object.
`GSA_REGISTRATION` is reused for the same MLS-GIKE registration content when a GM joins another group over an established IKE SA.
The response carries a non-installable GSA, optional KD for Sender-ID, and a KD-carried `mls_group_template` object only for the founder case.

`GSA_MLS_REQUEST_COMMIT` is a new GCKS-initiated IKEv2 request/response exchange.
The GCKS uses it to send an external Proposal to a designated committer.
The response is empty unless the designated committer immediately returns an error Notify.
The designated committer uploads the resulting Commit material separately with `GIKE_MLS_UPLOAD`.

`GSA_INBAND_REKEY` is reused for GCKS-to-GM unicast delivery of epoch-bound state and related MLS objects.
The GCKS uses it to deliver Welcomes and ratchet trees to newly added members and to fan out ordered Commits with the epoch-bound GSA.
When the message installs a new Data-Security SA, it carries the GSA payload and the relevant KD-carried MLS objects.
When the message only delivers a removal notice without a fresh GSA, the GSA payload is omitted.
The response follows the `GSA_INBAND_REKEY` response shape in Section 2.4.2 of {{RFC9838}} and is empty unless it carries an error Notify.

`GSA_REKEY` is optionally reused for multicast fan-out of ordered MLS control material.
When it carries MLS-GIKE Data-Security SA state, it carries the GSA payload and KD-carried MLS objects.
It MUST NOT carry `SA_KEY` material for ESP Data-Security SAs in this profile.
If the message also rotates the G-IKEv2 Rekey SA, the Rekey SA key material is generated by the GCKS and carried according to the Rekey SA key-management method in use, such as LKH.

`GIKE_MLS_UPLOAD` is a new GM-initiated IKEv2 request/response exchange.
It is used by the founder to upload the initial GroupInfo and ratchet tree, by a designated committer to upload tentative Commit material, and by a member to post a path-refresh Commit and PartialGroupInfo to the GCKS.
The request carries `N(MLS_OBJECT)` notifications.
The response is empty on success or carries an error Notify on rejection.

`MLS_COMMIT_REJECTED` is a new Notify Message Error Type defined by this document.
At least stale epoch, invalid signature, unauthorized proposal, tree validation failure, and unauthorized identity need to be distinguishable rejection reasons.


# Security Considerations

The security considerations of G-IKEv2 {{RFC9838}}, MLS {{RFC9420}}, and the MLS architecture {{RFC9750}} apply.
This section highlights the issues most specific to this integration.

The GCKS does not hold an MLS leaf in this design.
A passive compromise of the GCKS does not by itself reveal MLS epoch secrets, exporter output, or ESP Data-Security SA keys.
This is the main security improvement over a design in which compromise of a GCKS-held KEK exposes previous rekeys.

The previous statement has an important limit.
In this profile, the GCKS is also the MLS DS, AS, and external sender.
A compromised GCKS can authorize an attacker-controlled KeyPackage and ask an honest designated committer to add it.
Traffic after that malicious Add is visible to the attacker leaf.
OPEN QUESTION: How should this profile split the AS from the GCKS and rotate the external-sender key?

The GCKS can perform public validation of MLS handshakes but cannot perform all member-side MLS validation.
In particular, it cannot verify MLS membership MACs, confirmation tags, epoch secrets, exporter output, or ESP keys.
Members remain the cryptographic acceptance authority for MLS Commits and Welcome processing.
This document does not specify recovery if the GCKS accepts a public state that members later reject.
OPEN QUESTION: What repair, rollback, or resynchronization behavior is required for that case?

The GCKS orders Commits.
Commit authors keep the resulting epoch tentative until the GCKS fans the ordered Commit back to them.
This avoids requiring rollback when a tentative Commit loses a race or is rejected.

All Proposals and Commits are MLS PublicMessages in this profile.
This exposes MLS handshake metadata to the GCKS, which is already the G-IKEv2 control point and delivery service.
The messages are still confidentiality-protected on the wire by the IKEv2 `SK{}` envelope between each GM and the GCKS.
When optional multicast fan-out is used, ordered Commit material can also be visible to a removed GM in the `GSA_REKEY` message that removes it.
This does not disclose the new Data-Security SA key, because that key is derived from the new MLS epoch.
Without LKH or another Rekey SA rotation mechanism, a removed GM that still knows the current Rekey SA key can also read later `GSA_REKEY` messages protected by that Rekey SA.
If future multicast control-plane confidentiality from the removed GM is required, the GCKS rotates the Rekey SA with LKH or another specified broadcast-encryption mechanism.
The MLS committer never supplies the Rekey SA key, which avoids giving the committer a direct way to corrupt the GCKS's multicast Rekey SA state.

The Sender-ID mechanism remains security-critical for multi-sender ESP with counter-based modes.
Reusing MLS exporter output without Sender-ID partitioning would risk key and nonce reuse.
This draft therefore keeps `GROUP_SENDER`, `GWP_SENDER_ID_BITS`, and `GM_SENDER_ID` where required by {{RFC9838}} for authorized senders.
Because this profile uses a shared Data-Security SA key, receiver-only authorization is enforced as local IPsec policy and GCKS authorization, not by withholding the ESP traffic key from receivers.

Every accepted MLS epoch uses a fresh Data-Security SA SPI.
This lets receivers distinguish old-key and new-key packets during the activation and deactivation overlap controlled by GWP_ATD and GWP_DTD.

Removal has a residual acceptance window during that overlap.
A removed member cannot derive the new epoch key, but it can still know the previous epoch's ESP key and Sender-ID values.
If receivers keep accepting the old ESP SA during GWP_DTD, packets from the removed member can still be accepted until the old SA is deleted.
OPEN QUESTION: Should removal require zero overlap, receiver-side Sender-ID filtering, explicit old-SA deletion policy, or a combination of these mechanisms?

A member-issued path-refresh Commit MUST contain an empty proposal vector and a populated UpdatePath.
The GCKS rejects member-authored Commits that carry Add, Remove, Update, PreSharedKey, GroupContextExtensions, or proposals by reference.
This preserves the rule that only the GCKS proposes structural or policy changes.

A designated committer can deny service by refusing to commit a GCKS-authored Proposal.
The mitigation specified here is for the GCKS to retry with another non-blank leaf.
More advanced committer selection and reputation policies are not specified in this document.

The IKE identity and MLS credential need an explicit binding.
If the GCKS authorizes an IKE identity but accepts an unrelated MLS credential in the KeyPackage, authorization is split across layers in a way this draft does not intend.


# IANA Considerations

This document names several new protocol codepoints but does not assign final values.
If standardized, the draft is expected to request new IKEv2 Exchange Type values for `GSA_MLS_REQUEST_COMMIT` and `GIKE_MLS_UPLOAD`.
The existing `GSA_AUTH`, `GSA_REGISTRATION`, `GSA_INBAND_REKEY`, and `GSA_REKEY` exchange types are otherwise reused.
It is not expected to request new IKEv2 Payload Type values for MLS objects.
MLS objects are carried in the existing KD and Notify payloads.
It is expected to request a new `MLS_OBJECT` Group Key Bag Attribute and a new `MLS_OBJECT` Member Key Bag Attribute.
It is expected to request a new IKEv2 Notify Message Status Type value for `MLS_OBJECT`.
It is expected to request a new IKEv2 Notify Message Error Type value for `MLS_COMMIT_REJECTED`.
It is also expected to register the MLS exporter label used for ESP key derivation.

# Open Questions

This section records issues intentionally left open in this document.

The exact binding between `IDg` and the MLS `group_id` needs to be settled.
The simplest approach is to make them equal subject to MLS length constraints.
A derived value with a domain separator is another option.

The external-sender key needs a rotation procedure.
OPEN QUESTION: Can a GCKS-authored `GroupContextExtensions` Proposal replace the `external_senders` extension for this purpose?

The designated committer policy needs review.
The policy specified above uses the lowest non-blank eligible leaf because it is deterministic and easy to specify.

The rejection code structure for `MLS_COMMIT_REJECTED` needs to be specified.
This could be a single Notify with a subcode or separate Notify types.

The final MLS exporter label needs review.
This document uses `MLS-GIKE ESP key` as a descriptive placeholder.
The final string should be checked against MLS Exporter Labels registry guidance and IPsec/IKE naming practice.

--- back
