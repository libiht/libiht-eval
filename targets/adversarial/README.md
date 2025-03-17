# Adversarial Settings

This folder contains a collection of adversarial techniques aimed at detecting and evading dynamic binary instrumentation (DBI) tools. These techniques draw on concepts from the *jitmenot* component of the [PwIN](https://github.com/zhechkoz/PwIN) project and the [dbi-detector](https://github.com/dcdelia/dbi-detector) project, focusing on identifying or disrupting common DBI behaviors.

## Taxonomy

Following the high-level taxonomy from the diagram, the techniques here are organized into **Indirect** and **Direct** evasion approaches.

### Indirect Evasion Techniques

1. **Functional Limitation (FL)**
   - **FSBase Integrity Check `sample_`**
     Detects discrepancies in the `fsbase` register (e.g., via `rdfsbase` vs. `prctl`) to reveal potential instrumentation side effects.
   - **RIP Preservation Check**
     Verifies that the instruction pointer (RIP) is preserved after certain operations (e.g., syscalls), detecting code rewriting artifacts.

2. **Resource Limitation**
   - *[Not explicitly implemented here]*
     In general, this class of techniques would constrain memory, CPU, or other resources to detect or hinder DBI frameworks that require additional overhead.

### Direct Evasion Techniques

1. **Code Cache Artifact Detection**
   - **NX Page Execution Detection**
     Attempts to run code in non-executable pages, relying on standard memory protections that DBI frameworks may violate or mishandle.
   - **Self-Modifying Code (SMC) Detection**
     Checks whether runtime code modifications behave unexpectedly under instrumentation, which often struggles with SMC scenarios.
   - **VMLeave Pattern Detection**
     Searches for known “VMLeave” or similar instruction sequences in the instrumented code, revealing underlying DBI code caches or stubs.

2. **Environment Artifact Detection**
   - **Environment Variable Checks**
     Looks for environment variables commonly set by DBI frameworks (e.g., PIN, DynamoRIO, Valgrind) to facilitate instrumentation.
   - **Mapped File Analysis**
     Inspects `/proc/self/maps` for library or file names associated with instrumentation engines (e.g., `pinbin`, `dynamorio`).
   - **Page Permissions Check**
     Checks memory page permissions to detect unexpected behavior (e.g., read-write-execute) that may indicate DBI activity.

3. **Runtime Just-in-Time Compiler Overhead Detection**
   - **JIT Branch Overhead**
     Measures execution timing across multiple iterations of the same code path; significant overhead spikes can indicate a JIT-based DBI.
   - **JIT Library Loading Check**
     Loads and unloads standard libraries repeatedly to detect irregularities in how a JIT-based instrumentation engine handles dynamic linking.

## References

1. Z. Zhechev, “Security evaluation of dynamic binary instrumentation engines,” PhD Thesis, Department of Informatics, Technical University of Munich, Germany, 2018.
2. D. C. D’Elia, L. Invidia, F. Palmaro, and L. Querzoni, “Evaluating Dynamic Binary Instrumentation Systems for Conspicuous Features and Artifacts,” *Digital Threats*, vol. 3, no. 2, pp. 1–13, Jun. 2022, doi: 10.1145/3478520.
3. A. S. Filho, R. J. Rodríguez, and E. L. Feitosa, “Evasion and Countermeasures Techniques to Detect Dynamic Binary Instrumentation Frameworks,” *Digital Threats*, vol. 3, no. 2, p. 11:1-11:28, Feb. 2022, doi: 10.1145/3480463.
