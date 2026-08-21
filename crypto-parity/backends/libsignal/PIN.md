# libsignal reference pin

**Status: UNVERIFIED**

The parent VoiceChat application is **not** in this workspace. The exact
`libsignal` git revision VoiceChat currently vendors could not be read here.

Do not guess a commit. When the app repo is available, record:

```
repo:   signalapp/libsignal
commit: <sha>
date:   <iso>
note:   pin used by VoiceChat; do not upgrade during a parity run
```

## License isolation

`libsignal` is AGPL-3.0. This crate (`crypto-parity`) and `voicechat-crypto`
must **not** depend on it.

To run a real differential against libsignal:

1. Create a **separate**, AGPL-licensed repository.
2. Implement `Backend` there.
3. Feed it the same scenario IDs from `scenarios/*.yaml`.
4. Never copy that adapter into `voicechat-crypto`.

Until that exists, the in-tree adapter reports `NOT_LINKED`.
