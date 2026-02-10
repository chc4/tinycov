TinyCOV binary instrumentation
==============

Binary instrumentation using KVM, built on top of [TinyKVM](https://github.com/varnish/tinykvm).

# How

This uses *software breakpoints* in the guest userspace to implement coverage hooks: branches are replaced with an `INT3` instruction that when hit, take a ring-3 -> ring-3 exception to the guest kernel on a separate stack. The guest kernel can then track coverage items, or take a full vmexit to the host VMM for more processing.

The VMM traces basic blocks for exits, and when it finds one JITs an assembly snippet on a *trampoline page*. The exit is replaced with `INT3 <index>` where `<index>` encodes some metadata bits (such as if the branch hasn't been hit yet), along with selects a trampoline page. When the branch is hit the guest kernel uses the `<index>` byte to redirect the guest userspace to the assembly snippet on the correct trampoline page, and if it was the first time the branch was hit traces the basic blocks which are the successors of the exit to find more exits.

Currently this all happens in the host VMM for prototyping, but ideally most of it would happen in the guest kernel instead.

We currently don't support dynamic jumps, only conditionals and dynamic calls; this means binaries will have some missing coverage.

# Why

idk I mostly thought it would be neat. My laptop has an AMD processor so I can't use Intel PT like a normal person. Doing `INT3` based coverage hooks is kind of nice for a few reasons; for one, ring-3 -> ring-3 exceptions under kvm mean you don't actually need to switch privilege levels and are thus only like 80 cycles, and all other instructions run at native speed unlike with dynamic binary recompilation based approaches. Doing QEMU TCG based instrumentation means you have to write a custom TCG hook for whatever you want your coverage hook to do instead of being able to just write C code, either in the guest kernel or host VMM. Because we rewrite the branches *in place* with a single instruction, we also can dynamically (dis|en)able coverage for branches at runtime: you could imagine a fuzzer removing the coverage hook for branches that it has seen both true and false edges for, and then they go back to fully native speed.

# Why not

80 cycles per branch is still a lot. The big issue is also around dynamic calls and dynamic jumps: we need to know the dispatch target in order to push the coverage frontier through the potentialy unseen block, which means that we need to compute the dynamic dispatch target somehow. Right now there's a dumb Capstone based evaluator for this in the host VMM to resolve the dynamic dispatch target, which sucks. We can probably replace that with instead a two-step solution, where we take one `INT3` to the guest kernel to redirect to the trampoline, and then the trampoline computes the target and does another `INT3` to emit the coverage edge. But I haven't written that part yet.

# Testing

```
mkdir build && cmake -B build -DCMAKE_BUILD_TYPE=Release
make -j && ALL_PATHS=1 COVERAGE=1 /build/simplekvm <some binary> <some arguments>
```

And then remove `COVERAGE=1` to see how much faster it is without the instrumentation.

Run it on statically linked executables, or else you probably are missing most of the program due to TinyCOV missing the dynamic linker jumping to `_start`.
