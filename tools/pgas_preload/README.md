# PGAS Preload Library for Memcached

This library provides PGAS (Partitioned Global Address Space) memory operation hooks for memcached using LD_PRELOAD.

## Building

```bash
cd /root/splash/build
cmake -DBPFTIME_LLVM_JIT=OFF ..
make pgas_preload
```

The library will be built at: `lib/cxltime/tools/pgas_preload/libpgas_preload.so`

## Usage

### Basic Usage

```bash
# Start memcached with PGAS hooks
LD_PRELOAD=/path/to/libpgas_preload.so memcached -m 1024 -p 11211
```

### With Configuration

```bash
# Configure via environment variables
export PGAS_NODE_ID=0          # This node's ID (0-based)
export PGAS_NUM_NODES=4        # Total number of nodes
export PGAS_BASE_ADDR=0x0      # Base address of PGAS region
export PGAS_SIZE=1073741824    # Size in bytes (1GB)
export PGAS_VERBOSE=1          # Enable verbose logging
export PGAS_STATS=1            # Enable statistics (default)

LD_PRELOAD=/path/to/libpgas_preload.so memcached -m 1024 -p 11211
```

### With Configuration File

Create a config file (e.g., `pgas.conf`):

```ini
node_id=0
num_nodes=4
base_addr=0x0
size=1073741824
verbose=true
```

Then use:

```bash
PGAS_CONFIG=/path/to/pgas.conf LD_PRELOAD=/path/to/libpgas_preload.so memcached -m 1024
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PGAS_NODE_ID` | Local node identifier | 0 |
| `PGAS_NUM_NODES` | Total number of nodes | 1 |
| `PGAS_BASE_ADDR` | Base address of PGAS memory region | 0 |
| `PGAS_SIZE` | Size of PGAS region in bytes | 1GB |
| `PGAS_VERBOSE` | Enable verbose output (1/0) | 0 |
| `PGAS_STATS` | Enable statistics output (1/0) | 1 |
| `PGAS_CONFIG` | Path to configuration file | (none) |

## How It Works

1. **Library Loading**: When the library is loaded via LD_PRELOAD, the constructor function `pgas_preload_init()` is called automatically.

2. **Hook Installation**: The library hooks `memcpy`, `memmove`, and `memset` using Frida's interceptor.

3. **Address Routing**: Each memory operation is analyzed to determine which node owns the target address based on a simple hash-based partitioning scheme.

4. **Statistics Collection**: The library tracks:
   - Number of each operation type
   - Total bytes copied
   - Local vs remote access counts

5. **Cleanup**: When memcached exits, the destructor prints statistics and cleans up hooks.

## Statistics Output

When memcached exits (or on signal), you'll see output like:

```
=== PGAS Statistics ===
Node ID: 0 / 4
memcpy calls: 125000
memmove calls: 50
memset calls: 10000
Total bytes copied: 50000000
Local accesses: 31250
Remote accesses: 93750
Remote access ratio: 75.00%
========================
```

## Multi-Node Setup

For a 4-node memcached cluster:

**Node 0:**
```bash
PGAS_NODE_ID=0 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11211
```

**Node 1:**
```bash
PGAS_NODE_ID=1 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11212
```

**Node 2:**
```bash
PGAS_NODE_ID=2 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11213
```

**Node 3:**
```bash
PGAS_NODE_ID=3 PGAS_NUM_NODES=4 LD_PRELOAD=libpgas_preload.so memcached -p 11214
```

## Programmatic API

The library exports C functions that can be called at runtime:

```c
// Get current statistics
void pgas_get_stats(uint64_t *memcpy_calls, uint64_t *memmove_calls,
                    uint64_t *memset_calls, uint64_t *bytes_copied,
                    uint64_t *local_accesses, uint64_t *remote_accesses);

// Reset statistics
void pgas_reset_stats();

// Print statistics to stderr
void pgas_print_stats();

// Check if PGAS is initialized
int pgas_is_initialized();

// Get node configuration
void pgas_get_config(uint16_t *node_id, uint16_t *num_nodes,
                     uint64_t *base_addr, uint64_t *size);
```

## Extending for Real CXL/RDMA

The current implementation routes addresses to nodes but performs local memory operations. To implement actual distributed memory:

1. Modify the override handlers in `pgas_attach_impl.cpp`:
   - `pgas_memcpy_override_handler()`
   - `pgas_memmove_override_handler()`
   - `pgas_memset_override_handler()`

2. Add network transport code when `ctx->is_remote` is true:
   - For CXL: Use CXL.mem load/store semantics
   - For RDMA: Use ibverbs for remote memory access

## Troubleshooting

### Library not loading
```bash
# Check library dependencies
ldd /path/to/libpgas_preload.so

# Verify it loads
LD_DEBUG=libs LD_PRELOAD=/path/to/libpgas_preload.so /bin/true
```

### No hooks installed
- Ensure memcpy/memmove/memset symbols are found
- Check verbose output for errors

### Performance issues
- Disable verbose mode: `PGAS_VERBOSE=0`
- Disable statistics if not needed: `PGAS_STATS=0`
