# Insert Optimization Analysis

## Current Data Flow

### Dumpstate (Text Log)
```
dumpstate.log 
  ↓ preprocess() — yields dict per line
  ↓ tuple conversion — record.get(column) for each column
  ↓ insert_rows() — writes to temp CSV file
  ↓ DuckDB COPY FROM CSV
  ↓ final table
```

### PCAP (Binary Log)
```
sample.pcapng
  ↓ preprocess() — streams packets via tshark, yields dict per packet
  ↓ tuple conversion — record.get(column) for each column
  ↓ insert_rows() — writes to temp CSV file
  ↓ DuckDB COPY FROM CSV
  ↓ final table
```

## Why CSV Intermediate?

**DuckDB's `COPY FROM` is faster than individual INSERTs:**

| Method | Speed | Memory | Use Case |
|--------|-------|--------|----------|
| CSV + COPY | Fast (parallelized) | Low (streaming disk) | Large files (10GB+) |
| Batched INSERT | Medium | Medium (batches in memory) | Streaming source, unknown row count |
| Individual INSERT | Slow | Variable | Rare updates, small data |

**CSV advantages:**
- COPY is parallelized internally by DuckDB
- Bulk parsing is faster than Python tuple iteration
- Disk I/O is optimized for sequential writes
- Works well with row pre-counting (dumpstate: count lines first)

## Performance Characteristics

### Dumpstate (Text File)
- **Row count known upfront** → Can pre-count lines for progress bar
- **Large files common** (100MB-10GB) → CSV + COPY is ideal
- **Current approach is optimal** for this use case

### PCAP (Streaming Source)
- **Row count unknown** → `total_rows=None` in insert_rows()
- **Streaming source** (tshark subprocess) → No pre-count possible
- **Large files possible** (10GB+) → CSV still works but:
  - Must write entire stream to temp file first
  - No progress bar (total_rows=None)
  - Temp disk I/O overhead

## Optimization Opportunities

### Option 1: Skip Tuple Conversion (Negligible)
**Current:** `tuple(record.get(column) for column in insert_columns)`

This is already lazy (generator expression), so minimal overhead.

**Status:** Not worth optimizing.

### Option 2: Batched INSERT for PCAP (Medium Impact)
**New function:** `insert_rows_batched()` for streaming sources

```python
def insert_rows_batched(
    connection: DuckDBPyConnection,
    table_name: str,
    columns: Sequence[str],
    records: Iterable[Sequence[Any]],
    batch_size: int = 10_000,
) -> int:
    """Batch INSERT for streaming sources (no temp file, no row pre-count needed)."""
    batch = []
    inserted = 0
    
    for record in records:
        batch.append(record)
        if len(batch) >= batch_size:
            connection.executemany(
                f"INSERT INTO {table} VALUES (...)",
                batch
            )
            inserted += len(batch)
            batch = []
    
    if batch:
        connection.executemany(...)
        inserted += len(batch)
    
    return inserted
```

**Pros:**
- No temp file → Lower disk overhead for streaming
- No need for row pre-count
- Simpler for PCAP (tshark output can't be pre-counted)

**Cons:**
- Slower than COPY for very large files (10GB+)
- More INSERT statements → higher overhead

**When to use:** PCAP with moderate files (<1GB) or unknown size

### Option 3: DuckDB Memory Table (High Impact, Complex)
**Idea:** Insert into memory table first (faster), then COPY to disk

```python
# 1. Create memory table
connection.execute("CREATE TEMP TABLE _staging AS SELECT * FROM main LIMIT 0")

# 2. Fast INSERT into memory
# (much faster, no disk I/O)

# 3. COPY from memory to main table
connection.execute("INSERT INTO main SELECT * FROM _staging")
```

**Pros:**
- Combines speed of INSERT with finality of COPY
- No temp disk file needed
- Faster for medium files

**Cons:**
- Requires fitting table in RAM
- Memory pressure for large files

**When to use:** Medium files (100MB-1GB) with row pre-count available

### Option 4: Parallel Chunked CSV (Experimental)
**Idea:** Split PCAP into N chunks, insert in parallel

Only viable if tshark output can be parallelized (probably not worth it).

**Status:** Too complex, not recommended.

## Recommendation

### Current (Keep as-is)
- **Dumpstate:** CSV + COPY (optimal for large text files with row pre-count)
- **PCAP:** CSV + COPY (works but temp file overhead)

### Phase 2 (Optimize PCAP)
- **Add `insert_rows_batched()`** to database.py
- **Use for PCAP** if file size < 1GB OR total_rows is None
- **Keep CSV + COPY** for dumpstate (don't change)

### Phase 3 (Advanced, if needed)
- **Memory table approach** if PCAP files are 1-10GB and RAM available
- **Profile first** to measure actual bottleneck (likely tshark parsing, not insert)

## Profiling Checklist (Before Optimizing)

Before implementing any change:

1. **Measure actual bottleneck**
   ```bash
   time logdb make -i large.pcapng -t pcap -o test.duckdb
   ```
   - Is tshark slow? (subprocess overhead, parsing)
   - Is CSV write slow? (disk I/O)
   - Is DuckDB COPY slow? (insert execution)

2. **Test batch sizes**
   - Compare batch_size=1K, 10K, 100K for INSERT
   - Find sweet spot for your hardware

3. **Compare approaches**
   - Current CSV + COPY vs. batched INSERT
   - Measure wall-clock time and peak RAM

## Decision Points

| Scenario | Approach | Reason |
|----------|----------|--------|
| Dumpstate, any size | Keep CSV + COPY | Optimal for row pre-count |
| PCAP, <100MB | Use batched INSERT | Fast, no temp file |
| PCAP, 100MB-1GB | Batched INSERT or CSV | Depends on RAM, profile first |
| PCAP, >1GB | Keep CSV + COPY (or profile) | CSV safer for large files |
| HCI/other future types | TBD, profile first | Depends on source characteristics |

## Files Affected (When Implementing)

1. **database.py** — Add `insert_rows_batched()` function
2. **pcap/db_make.py** — Call `insert_rows_batched()` instead of `insert_rows()`
3. **dumpstate/db_make.py** — No changes (keep CSV + COPY)

## Notes

- CSV intermediate is **not** the bottleneck for most use cases
- **tshark parsing** (for PCAP) is likely the real bottleneck
- Optimize insert only after profiling tshark subprocess
- Keep CSV + COPY as default (safest, most tested path)
