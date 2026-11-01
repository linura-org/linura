# BlueZ provider

S19-1 is a **read-only** native observation provider for BlueZ 5 ObjectManager. S19-2 additionally exposes only passive Adapter1 discovery state as `bluez.discovery.observe`, explicitly without a verified owned discovery lease. It does not register StartDiscovery, StopDiscovery, power, connection, pairing, trust, block or RemoveDevice effects. It is installed in the daemon's existing Control-owned ObservationCoordinator, not exposed as an independent authority.

The system D-Bus unique owner is resolved and used as the destination of the GetManagedObjects request; owner and Linux boot identity are re-read after receipt. Resource identifiers additionally include the observed boot and unique owner epoch, so a stale enumeration cannot select a reused BlueZ object path under a different daemon owner or boot. Controller hotplug reuse within one provider epoch remains unverified and cannot authorize an effect. The reply's D-Bus body is byte-budgeted before deserialization. Parsed object, adapter, device, interface, property, alias and UUID counts are bounded and invalid or ambiguous native properties fail closed.

Device address, address type, parent adapter and distinct Paired/Trusted/Blocked/Connected/ServicesResolved properties are retained. Adapter1 `Discovering` is global aggregated native state, not proof of an owned scan, a discovery filter or an authorized right to stop any discovery session. Absent optional facts are **unknown**; a connected device is not necessarily service-ready. The observer explicitly reports that remote cryptographic identity and controller hotplug generation are **unverified**. No prepared or effectful action may rely on this observer alone for continuity.

S19-1 tests are deterministic parser/negative-path tests and do not imply a completed native exact-source BlueZ qualification. Native BlueZ owner restart, hotplug, physical radio and hardware acceptance remain separate required evidence. No virtual-HCI test can promote Q11 support.

Run on the exact WIP source head, and again on any future independently extracted PR:

- cargo test --locked -p linura-provider-bluez
- cargo test --locked -p linura-observation-control
- cargo test --locked -p linurad
- cargo xtask check
- applicable real BlueZ (not fake only) Level A qualification

All S19 development remains on `wip/v010-s19-bluetooth`; do not open implementation PRs before explicit extraction approval. Do not claim support while any required gate or native qualification remains unverified.
